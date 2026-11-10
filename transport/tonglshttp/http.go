// Package tonglshttp authenticates a Tongls tunnel through an ordinary
// HTTPS/1.1 Upgrade. It does not implement TLS, AnyTLS frames, or traffic shaping.
package tonglshttp

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	Protocol        = "tongls-v1"
	exporterLabel   = "EXPORTER-Tongls-v1"
	maxUsers        = 1024
	maxHeaderBytes  = 16 * 1024
	maxPaddingBytes = 4096
	selectorSize    = 16
	authSize        = selectorSize + sha256.Size
)

var ErrRejected = errors.New("tongls HTTPS upgrade rejected")

type User struct {
	Name     string
	Password string
}

type TLSConn interface {
	net.Conn
	ConnectionState() tls.ConnectionState
}

type credential struct {
	name string
	key  [sha256.Size]byte
}

type handler struct {
	users     map[[selectorSize]byte]credential
	dummyKey  [sha256.Size]byte
	path      string
	fallback  *httputil.ReverseProxy
	transport *http.Transport
	onUpgrade func(context.Context, net.Conn, string)
}

// NewHandler returns a handler for a native net/http TLS server. The result also
// implements io.Closer; its Close releases idle connections to the fixed backend.
// The caller owns TLS/header deadlines, connection limits and hijacked tunnels.
// Normal requests, including HTTP/2, are served by the same fixed HTTP backend.
func NewHandler(users []User, path string, fallbackURL *url.URL, onUpgrade func(context.Context, net.Conn, string)) (http.Handler, error) {
	path, err := NormalizePath(path)
	if err != nil {
		return nil, err
	}
	if fallbackURL == nil || fallbackURL.Scheme != "http" || fallbackURL.Host == "" || fallbackURL.User != nil || fallbackURL.Fragment != "" || fallbackURL.RawQuery != "" {
		return nil, errors.New("tongls fallback must be a fixed plaintext HTTP URL without credentials, query or fragment")
	}
	if onUpgrade == nil {
		return nil, errors.New("tongls upgrade handler is missing")
	}
	if len(users) == 0 || len(users) > maxUsers {
		return nil, fmt.Errorf("tongls requires between 1 and %d users", maxUsers)
	}
	names := make(map[string]bool, len(users))
	keys := make(map[[sha256.Size]byte]bool, len(users))
	credentials := make(map[[selectorSize]byte]credential, len(users))
	for index, user := range users {
		if user.Name == "" || user.Password == "" || names[user.Name] {
			return nil, fmt.Errorf("tongls user %d requires a unique name and nonempty password", index)
		}
		key := sha256.Sum256([]byte(user.Password))
		if keys[key] {
			return nil, fmt.Errorf("tongls user %d has a duplicate password", index)
		}
		selector := credentialSelector(key)
		if _, exists := credentials[selector]; exists {
			return nil, fmt.Errorf("tongls user %d has a colliding credential selector", index)
		}
		names[user.Name], keys[key] = true, true
		credentials[selector] = credential{name: user.Name, key: key}
	}
	var dummyKey [sha256.Size]byte
	if _, err = rand.Read(dummyKey[:]); err != nil {
		return nil, err
	}
	backend := *fallbackURL
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// This is an administrator-selected backend, not an environment-selected
	// HTTP proxy and never a destination supplied by the incoming request.
	transport.Proxy = nil
	transport.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxIdleConnsPerHost = 16
	proxy := httputil.NewSingleHostReverseProxy(&backend)
	proxy.Transport = transport
	return &handler{users: credentials, dummyKey: dummyKey, path: path, fallback: proxy, transport: transport, onUpgrade: onUpgrade}, nil
}

func (h *handler) Close() error {
	h.transport.CloseIdleConnections()
	return nil
}

func (h *handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	name, authenticated := h.authenticate(request)
	if !authenticated {
		// ReverseProxy removes Proxy-Authorization as a hop-by-hop field, just
		// as it does for an ordinary website proxy. End-to-end Authorization
		// remains available to the real website without special rewriting.
		h.fallback.ServeHTTP(writer, request)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		// HTTP/2 and handlers without hijacking support remain ordinary HTTP.
		h.fallback.ServeHTTP(writer, request)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + Protocol + "\r\n\r\n"); err != nil {
		return
	}
	if err = buffered.Flush(); err != nil {
		return
	}
	// net/http's header deadline must not become the tunnel's lifetime. The
	// caller's underlying managed socket can preserve its independent limits.
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return
	}
	h.onUpgrade(request.Context(), &bufferedConn{Conn: conn, reader: buffered.Reader}, name)
}

func (h *handler) authenticate(request *http.Request) (string, bool) {
	if request.TLS == nil || request.TLS.Version != tls.VersionTLS13 || !request.TLS.HandshakeComplete || request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.Method != http.MethodGet || request.RequestURI != h.path || request.ContentLength != 0 || len(request.TransferEncoding) != 0 {
		return "", false
	}
	if !hasToken(request.Header.Values("Connection"), "upgrade") || len(request.Header.Values("Upgrade")) != 1 || !strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), Protocol) {
		return "", false
	}
	values := request.Header.Values("Proxy-Authorization")
	if len(values) != 1 {
		return "", false
	}
	authorization, ok := decodeAuthorization(values[0])
	if !ok {
		return "", false
	}
	exported, err := request.TLS.ExportKeyingMaterial(exporterLabel, nil, sha256.Size)
	if err != nil {
		return "", false
	}
	selector := [selectorSize]byte(authorization[:selectorSize])
	user, exists := h.users[selector]
	key := user.key
	if !exists {
		key = h.dummyKey
	}
	// Both known and unknown selectors perform one request-proof HMAC. This
	// avoids per-user work amplification; it does not promise constant-time
	// map lookups or indistinguishable network timing.
	expected := makeProof(key, exported, request.Method, request.Host, request.RequestURI)
	matched := hmac.Equal(expected[:], authorization[selectorSize:])
	if !exists || !matched {
		return "", false
	}
	return user.name, true
}

// NormalizePath accepts an absolute, unambiguous escaped path. This is a routing
// value, not a secret. Query strings and fragments are intentionally unsupported.
func NormalizePath(path string) (string, error) {
	if path == "" {
		path = "/"
	}
	if len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#\r\n") {
		return "", errors.New("tongls path must be an absolute path without query or fragment")
	}
	parsed, err := url.ParseRequestURI(path)
	if err != nil || parsed.Host != "" || parsed.Scheme != "" || parsed.EscapedPath() != path {
		return "", errors.New("tongls path is invalid")
	}
	return path, nil
}

func NormalizePadding(minimum, maximum int) (int, int, error) {
	if minimum == 0 && maximum == 0 {
		minimum, maximum = 128, 512
	}
	if minimum < 0 || maximum < minimum || maximum > maxPaddingBytes {
		return 0, 0, fmt.Errorf("tongls header padding requires 0 <= min <= max <= %d", maxPaddingBytes)
	}
	return minimum, maximum, nil
}

// Client performs an HTTP/1.1 upgrade on an already verified TLS 1.3 connection.
// TLS session-bound HMAC authentication is independent of AnyTLS's inner login.
// Cancellation controls only the upgrade; a successful returned stream is not
// closed by a later cancellation. The caller must enforce an upgrade deadline.
func Client(ctx context.Context, conn TLSConn, host, path, password string, paddingMin, paddingMax int) (_ net.Conn, err error) {
	if conn == nil {
		return nil, errors.New("tongls TLS connection is missing")
	}
	completed := false
	cancelStopped := false
	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		abortConn(conn)
		close(cancelDone)
	})
	defer func() {
		if !completed {
			if !cancelStopped && !stopCancel() {
				<-cancelDone
			}
			abortConn(conn)
			if ctxErr := ctx.Err(); ctxErr != nil {
				err = ctxErr
			}
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	path, err = NormalizePath(path)
	if err != nil {
		return nil, err
	}
	paddingMin, paddingMax, err = NormalizePadding(paddingMin, paddingMax)
	if err != nil {
		return nil, err
	}
	if password == "" || host == "" || strings.ContainsAny(host, " /\\\t\r\n?#@") {
		return nil, errors.New("tongls requires a password and valid HTTP host")
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version != tls.VersionTLS13 || len(state.VerifiedChains) == 0 || state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return nil, errors.New("tongls requires verified TLS 1.3 with HTTP/1.1")
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil || request.URL.Host != host || request.URL.RequestURI() != path {
		return nil, errors.New("tongls HTTP request is invalid")
	}
	exported, err := state.ExportKeyingMaterial(exporterLabel, nil, sha256.Size)
	if err != nil {
		return nil, fmt.Errorf("tongls TLS exporter unavailable: %w", err)
	}
	key := sha256.Sum256([]byte(password))
	proof := makeProof(key, exported, request.Method, request.Host, request.URL.RequestURI())
	request.Header.Set("Proxy-Authorization", encodeAuthorization(key, proof))
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", Protocol)
	padding, err := randomPadding(paddingMin, paddingMax)
	if err != nil {
		return nil, err
	}
	if padding != "" {
		request.Header.Set("Padding", padding)
	}
	if err = request.Write(conn); err != nil {
		return nil, err
	}
	limited := &headerReader{reader: conn, remaining: maxHeaderBytes}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("tongls read upgrade response: %w", err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols || response.ProtoMajor != 1 || response.ProtoMinor != 1 || !hasToken(response.Header.Values("Connection"), "upgrade") || len(response.Header.Values("Upgrade")) != 1 || !strings.EqualFold(strings.TrimSpace(response.Header.Get("Upgrade")), Protocol) {
		return nil, ErrRejected
	}
	limited.remaining = -1
	if !stopCancel() {
		<-cancelDone
		return nil, ctx.Err()
	}
	cancelStopped = true
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	completed = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func makeProof(key [sha256.Size]byte, exported []byte, method, host, target string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("Tongls-v1 request\x00"))
	mac.Write(exported)
	for _, field := range []string{method, host, target} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		mac.Write(length[:])
		mac.Write([]byte(field))
	}
	var proof [sha256.Size]byte
	copy(proof[:], mac.Sum(nil))
	return proof
}

func abortConn(conn net.Conn) {
	// A canceled handshake must not wait for a TLS close_notify write to an
	// unresponsive peer. Native TLS and sing's TLS adapters expose the socket.
	if tlsConn, ok := conn.(interface{ NetConn() net.Conn }); ok {
		_ = tlsConn.NetConn().Close()
		return
	}
	_ = conn.Close()
}

func credentialSelector(key [sha256.Size]byte) [selectorSize]byte {
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte("Tongls-v1 credential selector"))
	return [selectorSize]byte(mac.Sum(nil)[:selectorSize])
}

func encodeAuthorization(key, proof [sha256.Size]byte) string {
	var authorization [authSize]byte
	selector := credentialSelector(key)
	copy(authorization[:selectorSize], selector[:])
	copy(authorization[selectorSize:], proof[:])
	return "Tongls " + base64.StdEncoding.EncodeToString(authorization[:])
}

func decodeAuthorization(value string) ([authSize]byte, bool) {
	var proof [authSize]byte
	if len(value) > 128 {
		return proof, false
	}
	fields := strings.Fields(value)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Tongls") || len(fields[1]) != base64.StdEncoding.EncodedLen(authSize) {
		return proof, false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(fields[1])
	if err != nil || len(decoded) != authSize || base64.StdEncoding.EncodeToString(decoded) != fields[1] {
		return proof, false
	}
	copy(proof[:], decoded)
	return proof, true
}

func hasToken(values []string, token string) bool {
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func randomPadding(minimum, maximum int) (string, error) {
	length := minimum
	if maximum > minimum {
		value, err := rand.Int(rand.Reader, big.NewInt(int64(maximum-minimum+1)))
		if err != nil {
			return "", err
		}
		length += int(value.Int64())
	}
	if length == 0 {
		return "", nil
	}
	buffer := make([]byte, length)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for index := range buffer {
		buffer[index] = alphabet[buffer[index]&63]
	}
	return string(buffer), nil
}

type bufferedConn struct {
	net.Conn
	readMu sync.Mutex
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.reader.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.New("tongls underlying connection does not support half-close")
}

type headerReader struct {
	reader    io.Reader
	remaining int
}

func (r *headerReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, errors.New("tongls upgrade response headers exceed limit")
	}
	if r.remaining > 0 && len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	if r.remaining > 0 {
		r.remaining -= n
	}
	return n, err
}
