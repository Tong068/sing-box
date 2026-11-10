package tongls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	original "github.com/sagernet/sing-box/protocol/anytls"
	wire "github.com/sagernet/sing-box/transport/tongls"
	"github.com/sagernet/sing-box/transport/tonglshttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type privateTestCredentials struct {
	certificate string
	key         string
	password    string
	pool        *x509.CertPool
}

func privateCredentials(t testing.TB) privateTestCredentials {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tongls.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"tongls.test"}, BasicConstraintsValid: true, IsCA: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var password [32]byte
	if _, err = rand.Read(password[:]); err != nil {
		t.Fatal(err)
	}
	credentials := privateTestCredentials{
		certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		key:         string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		password:    base64.StdEncoding.EncodeToString(password[:]), pool: x509.NewCertPool(),
	}
	if !credentials.pool.AppendCertsFromPEM([]byte(credentials.certificate)) {
		t.Fatal("cannot trust test certificate")
	}
	return credentials
}

type privateTestRouter struct {
	adapter.Router
	calls atomic.Int32
	route func(context.Context, net.Conn, adapter.InboundContext, N.CloseHandlerFunc)
}

func (r *privateTestRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.calls.Add(1)
	if r.route == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errors.New("unexpected proxy route"))
		return
	}
	r.route(ctx, conn, metadata, onClose)
}

func privateEchoRouter() *privateTestRouter {
	return &privateTestRouter{route: func(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
		defer conn.Close()
		err := N.ReportConnHandshakeSuccess(conn, conn)
		if err == nil {
			_, err = io.Copy(conn, conn)
		}
		if onClose != nil {
			onClose(err)
		}
	}}
}

func privateServerOptions(address string) option.ServerOptions {
	destination := M.ParseSocksaddr(address)
	return option.ServerOptions{Server: destination.AddrString(), ServerPort: destination.Port}
}

func privateInboundOptions(credentials privateTestCredentials, backend string) option.TonglsInboundOptions {
	fallback := privateServerOptions(backend)
	return option.TonglsInboundOptions{
		ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1")))},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled: true, Certificate: []string{credentials.certificate}, Key: []string{credentials.key},
		}},
		Users:    []option.TonglsUser{{Name: "private-user", Password: credentials.password}},
		Fallback: &fallback, Path: "/gate",
		HandshakeTimeout: badoption.Duration(2 * time.Second), IdleTimeout: badoption.Duration(3 * time.Second),
	}
}

func privateOutboundOptions(credentials privateTestCredentials, address string) option.TonglsOutboundOptions {
	return option.TonglsOutboundOptions{
		ServerOptions: privateServerOptions(address), Password: credentials.password,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled: true, ServerName: "tongls.test", Certificate: []string{credentials.certificate},
		}},
		Path: "/gate", HandshakeTimeout: badoption.Duration(2 * time.Second),
	}
}

type privateTestServer struct {
	address    string
	inbound    *Inbound
	scope      *adapter.Scope
	handshakes atomic.Int32
}

func startPrivateInbound(t testing.TB, router *privateTestRouter, options option.TonglsInboundOptions) *privateTestServer {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	instance, err := NewInbound(context.Background(), router, logger, "private-in", options)
	if err != nil {
		t.Fatal(err)
	}
	if instance.Type() != C.TypeTongls {
		t.Fatalf("Tongls inbound registered as %q", instance.Type())
	}
	server := &privateTestServer{inbound: instance.(*Inbound), scope: adapter.NewScope(context.Background(), logger)}
	t.Cleanup(func() { server.scope.Close() })
	config, err := server.inbound.tlsConfig.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	original := config.GetConfigForClient
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		server.handshakes.Add(1)
		if original != nil {
			return original(hello)
		}
		return nil, nil
	}
	if err = instance.Start(adapter.StartStateStart, server.scope); err != nil {
		t.Fatal(err)
	}
	server.address = server.inbound.private.listener.Addr().String()
	return server
}

func startPrivateOutbound(t testing.TB, options option.TonglsOutboundOptions) (*Outbound, *adapter.Scope) {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	instance, err := NewOutbound(context.Background(), nil, logger, "private-out", options)
	if err != nil {
		t.Fatal(err)
	}
	if instance.Type() != C.TypeTongls {
		t.Fatalf("Tongls outbound registered as %q", instance.Type())
	}
	scope := adapter.NewScope(context.Background(), logger)
	t.Cleanup(func() { scope.Close() })
	if err = instance.(*Outbound).Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	return instance.(*Outbound), scope
}

// The baseline instantiates the untouched AnyTLS adapter. Keep its ephemeral
// listener bound while injecting accepted connections, avoiding a port race.
func startOrdinaryInbound(t testing.TB, router *privateTestRouter, credentials privateTestCredentials) *privateTestServer {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	ctx, cancel := context.WithCancel(context.Background())
	options := option.AnyTLSInboundOptions{
		Users: []option.AnyTLSUser{{Name: "ordinary-user", Password: credentials.password}},
		InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{TLS: &option.InboundTLSOptions{
			Enabled: true, MinVersion: "1.3", MaxVersion: "1.3",
			Certificate: []string{credentials.certificate}, Key: []string{credentials.key},
		}},
	}
	instance, err := original.NewInbound(ctx, router, logger, "ordinary-in", options)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if instance.Type() != C.TypeAnyTLS {
		t.Fatalf("original AnyTLS inbound registered as %q", instance.Type())
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server := &privateTestServer{address: listener.Addr().String()}
	var mutex sync.Mutex
	active := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// All benchmark connections perform exactly one verified TLS
			// handshake. Counting accepted connections also detects reuse.
			server.handshakes.Add(1)
			mutex.Lock()
			active[conn] = struct{}{}
			mutex.Unlock()
			workers.Go(func() {
				defer func() {
					mutex.Lock()
					delete(active, conn)
					mutex.Unlock()
					conn.Close()
				}()
				instance.(adapter.ConnectionHandler).NewConnection(ctx, conn, adapter.InboundContext{
					Source: M.SocksaddrFromNet(conn.RemoteAddr()),
				}, nil)
			})
		}
	})
	t.Cleanup(func() {
		cancel()
		listener.Close()
		mutex.Lock()
		for conn := range active {
			conn.Close()
		}
		mutex.Unlock()
		workers.Wait()
	})
	return server
}

func startOrdinaryOutbound(t testing.TB, options option.TonglsOutboundOptions) (*original.Outbound, *adapter.Scope) {
	t.Helper()
	logger := log.NewNOPFactory().Logger()
	instance, err := original.NewOutbound(context.Background(), nil, logger, "ordinary-out", option.AnyTLSOutboundOptions{
		DialerOptions: options.DialerOptions, ServerOptions: options.ServerOptions,
		OutboundTLSOptionsContainer: options.OutboundTLSOptionsContainer,
		Password:                    options.Password, ClientMetadata: options.ClientMetadata,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval,
		IdleSessionTimeout:       options.IdleSessionTimeout, MinIdleSession: options.MinIdleSession,
	})
	if err != nil {
		t.Fatal(err)
	}
	if instance.Type() != C.TypeAnyTLS {
		t.Fatalf("original AnyTLS outbound registered as %q", instance.Type())
	}
	scope := adapter.NewScope(context.Background(), logger)
	t.Cleanup(func() { scope.Close() })
	client := instance.(*original.Outbound)
	if err = client.Start(adapter.StartStateInitialize, scope); err != nil {
		t.Fatal(err)
	}
	return client, scope
}

type comparisonClient interface {
	DialContext(context.Context, string, M.Socksaddr) (net.Conn, error)
	InterfaceUpdated(context.Context)
}

func TestTonglsPreservesOriginalAnyTLS(t *testing.T) {
	credentials := privateCredentials(t)
	router := privateEchoRouter()
	server := startOrdinaryInbound(t, router, credentials)
	client, _ := startOrdinaryOutbound(t, privateOutboundOptions(credentials, server.address))
	conn, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("original AnyTLS remains independently usable")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, received); err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("original AnyTLS round trip failed: %q, %v", received, err)
	}
}

func dialPrivateTLS(t testing.TB, credentials privateTestCredentials, address string, protocols ...string) *tls.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{
		RootCAs: credentials.pool, ServerName: "tongls.test", MinVersion: tls.VersionTLS13,
		NextProtos: protocols,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.(*tls.Conn)
}

func TestTonglsRoundTripAndReuse(t *testing.T) {
	credentials := privateCredentials(t)
	router := privateEchoRouter()
	server := startPrivateInbound(t, router, privateInboundOptions(credentials, "127.0.0.1:1"))
	client, _ := startPrivateOutbound(t, privateOutboundOptions(credentials, server.address))
	for index := range 4 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.org:443"))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		payload := bytes.Repeat([]byte{byte(index + 1)}, 32*1024+index)
		if _, err = conn.Write(payload); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		received := make([]byte, len(payload))
		if _, err = io.ReadFull(conn, received); err != nil {
			conn.Close()
			t.Fatal(err)
		}
		conn.Close()
		if !bytes.Equal(received, payload) {
			t.Fatal("proxy changed payload")
		}
	}
	if got := router.calls.Load(); got != 4 {
		t.Fatalf("routed streams=%d, want4", got)
	}
	if got := server.handshakes.Load(); got != 1 {
		t.Fatalf("TLS handshakes=%d, want1 for sequentially reused session", got)
	}
}

type fragmentedPrivateAuthConn struct {
	net.Conn
	firstWrite bool
}

func (c *fragmentedPrivateAuthConn) Write(p []byte) (int, error) {
	if c.firstWrite {
		return c.Conn.Write(p)
	}
	c.firstWrite = true
	// Each inner authentication byte becomes a separate TLS application record.
	// TCP framing or TLS record boundaries must not redefine authentication.
	for index := range p {
		if _, err := c.Conn.Write(p[index : index+1]); err != nil {
			return index, err
		}
	}
	return len(p), nil
}

func TestTonglsFragmentedInnerAuthentication(t *testing.T) {
	credentials := privateCredentials(t)
	router := privateEchoRouter()
	server := startPrivateInbound(t, router, privateInboundOptions(credentials, "127.0.0.1:1"))
	client, err := wire.NewClient(wire.ClientOptions{
		Password:             credentials.password,
		InitialPaddingScheme: wire.TonglsPaddingScheme,
		DialOut: func(ctx context.Context) (net.Conn, error) {
			dialer := tls.Dialer{Config: &tls.Config{
				RootCAs: credentials.pool, ServerName: "tongls.test", MinVersion: tls.VersionTLS13,
				NextProtos: []string{"http/1.1"},
			}}
			conn, err := dialer.DialContext(ctx, "tcp", server.address)
			if err != nil {
				return nil, err
			}
			upgraded, err := tonglshttp.Client(ctx, conn.(*tls.Conn), "tongls.test", "/gate", credentials.password, 0, 0)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return &fragmentedPrivateAuthConn{Conn: upgraded}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, M.ParseSocksaddr("example.org:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("fragmented authentication remains valid")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, received); err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("fragmented authentication failed: payload=%q error=%v", received, err)
	}
	if router.calls.Load() != 1 {
		t.Fatal("fragmented authentication was not routed exactly once")
	}
}

func TestTonglsBindsInnerUserToHTTPSUser(t *testing.T) {
	credentials := privateCredentials(t)
	secondPassword := privateCredentials(t).password
	for _, match := range []bool{false, true} {
		t.Run(fmt.Sprintf("matching-identities=%v", match), func(t *testing.T) {
			options := privateInboundOptions(credentials, "127.0.0.1:1")
			options.Users = append(options.Users, option.TonglsUser{Name: "second-user", Password: secondPassword})
			router := privateEchoRouter()
			server := startPrivateInbound(t, router, options)
			outerPassword := credentials.password
			if match {
				outerPassword = secondPassword
			}
			client, err := wire.NewClient(wire.ClientOptions{
				Password: secondPassword, InitialPaddingScheme: wire.TonglsPaddingScheme,
				DialOut: func(ctx context.Context) (net.Conn, error) {
					dialer := tls.Dialer{Config: &tls.Config{
						RootCAs: credentials.pool, ServerName: "tongls.test", MinVersion: tls.VersionTLS13,
						NextProtos: []string{"http/1.1"},
					}}
					conn, err := dialer.DialContext(ctx, "tcp", server.address)
					if err != nil {
						return nil, err
					}
					upgraded, err := tonglshttp.Client(ctx, conn.(*tls.Conn), "tongls.test", "/gate", outerPassword, 0, 0)
					if err != nil {
						conn.Close()
						return nil, err
					}
					return upgraded, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, M.ParseSocksaddr("example.org:443"))
			var received [1]byte
			if err == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, err = conn.Write([]byte{42}); err == nil {
					_, err = io.ReadFull(conn, received[:])
				}
			}
			if match {
				if err != nil || received[0] != 42 || router.calls.Load() != 1 {
					t.Fatalf("matching second-user identities failed: response=%v routes=%d err=%v", received, router.calls.Load(), err)
				}
			} else {
				if err == nil {
					t.Fatal("HTTPS user A entered AnyTLS as user B")
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("identity mismatch was not rejected promptly")
				}
				if router.calls.Load() != 0 {
					t.Fatal("mismatched identities reached the proxy router")
				}
			}
		})
	}
}

func TestTonglsUnauthenticatedRequestsUseWebsite(t *testing.T) {
	credentials := privateCredentials(t)
	var privateAuthForwarded atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.Header.Get("Proxy-Authorization"), "Tongls ") {
			privateAuthForwarded.Store(true)
		}
		writer.Header().Set("Content-Type", "text/plain")
		writer.Header().Set("X-Website", "real-backend")
		writer.Header().Set("X-Origin-Authorization", request.Header.Get("Authorization"))
		writer.WriteHeader(http.StatusOK)
		fmt.Fprintf(writer, "website:%s", request.URL.RequestURI())
	}))
	defer backend.Close()
	router := new(privateTestRouter)
	server := startPrivateInbound(t, router, privateInboundOptions(credentials, strings.TrimPrefix(backend.URL, "http://")))
	for _, protocol := range []string{"http/1.1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			transport := &http.Transport{
				TLSClientConfig:   &tls.Config{RootCAs: credentials.pool, ServerName: "tongls.test", MinVersion: tls.VersionTLS13},
				ForceAttemptHTTP2: protocol == "h2",
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, auth := range []string{"", "Tongls invalid-proof"} {
					path := "/gate?normal=1"
					if auth != "" {
						path = "/gate"
					}
					request, err := http.NewRequest(method, "https://"+server.address+path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if auth != "" {
						request.Header.Set("Proxy-Authorization", auth)
						if protocol == "http/1.1" {
							request.Header.Set("Connection", "Upgrade")
							request.Header.Set("Upgrade", "tongls-v1")
						}
					}
					request.Header.Set("Authorization", "Bearer normal-website-token")
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusOK || response.Header.Get("X-Website") != "real-backend" {
						t.Fatalf("request did not receive website: %s headers=%v", response.Status, response.Header)
					}
					if response.Header.Get("X-Origin-Authorization") != "Bearer normal-website-token" {
						t.Fatal("private gate altered ordinary website authentication")
					}
					if protocol == "h2" && response.ProtoMajor != 2 {
						t.Fatalf("HTTP/2 fallback negotiated %s", response.Proto)
					}
					want := "website:" + path
					if method == http.MethodHead {
						want = ""
					}
					if string(body) != want {
						t.Fatalf("website response=%q, want%q", body, want)
					}
				}
			}
		})
	}
	if privateAuthForwarded.Load() {
		t.Fatal("private proof leaked to website backend")
	}
	if router.calls.Load() != 0 {
		t.Fatal("unauthenticated website request reached proxy router")
	}
}

func TestTonglsShortHTTPWithoutALPN(t *testing.T) {
	credentials := privateCredentials(t)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { io.WriteString(writer, "short request accepted") }))
	defer backend.Close()
	router := new(privateTestRouter)
	server := startPrivateInbound(t, router, privateInboundOptions(credentials, strings.TrimPrefix(backend.URL, "http://")))
	conn := dialPrivateTLS(t, credentials, server.address)
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "short request accepted" {
		t.Fatalf("short request did not behave as a website: status=%s body=%q err=%v", response.Status, body, err)
	}
	if router.calls.Load() != 0 {
		t.Fatal("short HTTP request reached proxy router")
	}
}

func TestTonglsWebsiteProbeBeforeAfter(t *testing.T) {
	credentials := privateCredentials(t)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-Website", "actual-backend")
		io.WriteString(writer, "normal website response")
	}))
	defer backend.Close()
	for _, private := range []bool{false, true} {
		t.Run(fmt.Sprintf("private=%v", private), func(t *testing.T) {
			router := new(privateTestRouter)
			var server *privateTestServer
			if private {
				server = startPrivateInbound(t, router, privateInboundOptions(credentials, strings.TrimPrefix(backend.URL, "http://")))
			} else {
				server = startOrdinaryInbound(t, router, credentials)
			}
			conn := dialPrivateTLS(t, credentials, server.address)
			conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: tongls.test\r\nConnection: close\r\n\r\n"); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if !private {
				if err == nil {
					response.Body.Close()
					t.Fatal("ordinary AnyTLS unexpectedly answered a website probe")
				}
				if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
					t.Fatal("ordinary AnyTLS baseline timed out instead of closing")
				}
				t.Log("ordinary AnyTLS: GET closed without an HTTP response")
			} else {
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(response.Body)
				response.Body.Close()
				if readErr != nil || response.StatusCode != http.StatusOK || response.Header.Get("X-Website") != "actual-backend" || string(body) != "normal website response" {
					t.Fatalf("private mode did not return real website: status=%s body=%q err=%v", response.Status, body, readErr)
				}
				t.Log("private AnyTLS: same GET received the actual website's HTTP 200 response")
			}
			if router.calls.Load() != 0 {
				t.Fatal("website probe reached proxy router")
			}
		})
	}
}

func TestTonglsRejectsWrongPasswordAndLegacyClient(t *testing.T) {
	credentials := privateCredentials(t)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { io.WriteString(writer, "ordinary website") }))
	defer backend.Close()
	router := new(privateTestRouter)
	server := startPrivateInbound(t, router, privateInboundOptions(credentials, strings.TrimPrefix(backend.URL, "http://")))
	for _, variant := range []string{"wrong-password", "legacy-client"} {
		t.Run(variant, func(t *testing.T) {
			options := privateOutboundOptions(credentials, server.address)
			var client comparisonClient
			if variant == "wrong-password" {
				options.Password = "wrong-password-cannot-authenticate"
				client, _ = startPrivateOutbound(t, options)
			} else {
				client, _ = startOrdinaryOutbound(t, options)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.org:443"))
			if err == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, err = conn.Write([]byte("probe")); err == nil {
					var one [1]byte
					_, err = conn.Read(one[:])
				}
			}
			if err == nil {
				t.Fatal("client bypassed the private HTTP authentication gate")
			}
		})
	}
	if router.calls.Load() != 0 {
		t.Fatal("unauthorized client reached proxy router")
	}
}

func TestTonglsCertificateVerification(t *testing.T) {
	credentials := privateCredentials(t)
	server := startPrivateInbound(t, privateEchoRouter(), privateInboundOptions(credentials, "127.0.0.1:1"))
	for _, variant := range []string{"wrong-host", "untrusted-root"} {
		t.Run(variant, func(t *testing.T) {
			options := privateOutboundOptions(credentials, server.address)
			if variant == "wrong-host" {
				options.TLS.ServerName = "wrong-host.invalid"
			} else {
				options.TLS.Certificate = []string{privateCredentials(t).certificate}
			}
			client, _ := startPrivateOutbound(t, options)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("example.org:443"))
			if err == nil {
				conn.Close()
				t.Fatal("private client accepted invalid server identity")
			}
		})
	}
}

func TestTonglsHeaderTimeoutAndConnectionLimit(t *testing.T) {
	credentials := privateCredentials(t)
	options := privateInboundOptions(credentials, "127.0.0.1:1")
	options.HandshakeTimeout = badoption.Duration(500 * time.Millisecond)
	options.MaxConnections = 1
	server := startPrivateInbound(t, new(privateTestRouter), options)
	first := dialPrivateTLS(t, credentials, server.address, "http/1.1")
	if _, err := io.WriteString(first, "G"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{RootCAs: credentials.pool, ServerName: "tongls.test", MinVersion: tls.VersionTLS13}}
	if second, err := dialer.DialContext(ctx, "tcp", server.address); err == nil {
		second.Close()
		t.Fatal("connection cap did not include pending HTTP headers")
	}
	first.SetReadDeadline(time.Now().Add(time.Second))
	_, err := io.ReadAll(first)
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("incomplete HTTP header survived the handshake timeout")
	}
	// The timed-out connection must also release its admission slot.
	replacement := dialPrivateTLS(t, credentials, server.address, "http/1.1")
	replacement.Close()
}

func TestTonglsInnerAuthenticationTimeout(t *testing.T) {
	credentials := privateCredentials(t)
	options := privateInboundOptions(credentials, "127.0.0.1:1")
	options.HandshakeTimeout = badoption.Duration(300 * time.Millisecond)
	options.IdleTimeout = badoption.Duration(3 * time.Second)
	options.MaxConnections = 1
	router := new(privateTestRouter)
	server := startPrivateInbound(t, router, options)
	tlsConn := dialPrivateTLS(t, credentials, server.address, "http/1.1")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	upgraded, err := tonglshttp.Client(ctx, tlsConn, "tongls.test", "/gate", credentials.password, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()
	upgraded.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err = upgraded.Read(one[:]); err == nil {
		t.Fatal("server sent private protocol bytes without inner authentication")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("authenticated upgrade bypassed the inner authentication timeout")
	}
	if router.calls.Load() != 0 {
		t.Fatal("incomplete inner authentication reached proxy router")
	}
	replacement := dialPrivateTLS(t, credentials, server.address, "http/1.1")
	replacement.Close()
}

func TestTonglsOutboundScopeClosesSession(t *testing.T) {
	credentials := privateCredentials(t)
	server := startPrivateInbound(t, privateEchoRouter(), privateInboundOptions(credentials, "127.0.0.1:1"))
	client, scope := startPrivateOutbound(t, privateOutboundOptions(credentials, server.address))
	conn, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err = io.ReadFull(conn, one[:]); err != nil || one[0] != 42 {
		t.Fatalf("initial round trip failed: %v", err)
	}
	if err = scope.Close(); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = conn.Read(one[:]); err == nil {
		t.Fatal("private stream survived outbound scope close")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("outbound scope close did not interrupt stream read")
	}
}

func TestTonglsScopeClosesHijackedSession(t *testing.T) {
	credentials := privateCredentials(t)
	ready := make(chan struct{}, 1)
	router := &privateTestRouter{route: func(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
		defer conn.Close()
		err := N.ReportConnHandshakeSuccess(conn, conn)
		if err == nil {
			var one [1]byte
			_, err = io.ReadFull(conn, one[:])
			ready <- struct{}{}
			if err == nil {
				_, err = io.Copy(io.Discard, conn)
			}
		}
		if onClose != nil {
			onClose(err)
		}
	}}
	server := startPrivateInbound(t, router, privateInboundOptions(credentials, "127.0.0.1:1"))
	client, _ := startPrivateOutbound(t, privateOutboundOptions(credentials, server.address))
	conn, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not receive payload")
	}
	if err = server.scope.Close(); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err = conn.Read(one[:]); err == nil {
		t.Fatal("hijacked session survived inbound shutdown")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("inbound shutdown failed to interrupt session read")
	}
	if raw, err := net.DialTimeout("tcp", server.address, 200*time.Millisecond); err == nil {
		raw.Close()
		t.Fatal("private listener survived scope shutdown")
	}
}

func TestTonglsOptionsValidation(t *testing.T) {
	credentials := privateCredentials(t)
	logger := log.NewNOPFactory().Logger()
	for _, test := range []struct {
		name   string
		mutate func(*option.TonglsInboundOptions)
	}{
		{"no-tls", func(o *option.TonglsInboundOptions) { o.TLS = nil }},
		{"missing-fallback", func(o *option.TonglsInboundOptions) { o.Fallback = nil }},
		{"invalid-fallback", func(o *option.TonglsInboundOptions) { o.Fallback.ServerPort = 0 }},
		{"invalid-path", func(o *option.TonglsInboundOptions) { o.Path = "https://external.invalid/" }},
		{"negative-timeout", func(o *option.TonglsInboundOptions) { o.HandshakeTimeout = -1 }},
		{"negative-idle", func(o *option.TonglsInboundOptions) { o.IdleTimeout = -1 }},
		{"negative-limit", func(o *option.TonglsInboundOptions) { o.MaxConnections = -1 }},
		{"excess-limit", func(o *option.TonglsInboundOptions) { o.MaxConnections = 65537 }},
		{"unknown-alpn", func(o *option.TonglsInboundOptions) { o.TLS.ALPN = []string{"other"} }},
		{"empty-users", func(o *option.TonglsInboundOptions) { o.Users = nil }},
		{"oversized-auth-padding", func(o *option.TonglsInboundOptions) {
			o.PaddingScheme = []string{"stop=2", "0=65536-65536", "1=100-400"}
		}},
	} {
		t.Run("inbound/"+test.name, func(t *testing.T) {
			options := privateInboundOptions(credentials, "127.0.0.1:8080")
			test.mutate(&options)
			if _, err := NewInbound(context.Background(), new(privateTestRouter), logger, "invalid", options); err == nil {
				t.Fatal("invalid private inbound configuration accepted")
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(*option.TonglsOutboundOptions)
	}{
		{"insecure", func(o *option.TonglsOutboundOptions) { o.TLS.Insecure = true }},
		{"wrong-alpn", func(o *option.TonglsOutboundOptions) { o.TLS.ALPN = []string{"h2"} }},
		{"non-go-engine", func(o *option.TonglsOutboundOptions) { o.TLS.Engine = "windows" }},
		{"tls12", func(o *option.TonglsOutboundOptions) { o.TLS.MinVersion = "1.2" }},
		{"bad-path", func(o *option.TonglsOutboundOptions) { o.Path = "relative" }},
		{"negative-timeout", func(o *option.TonglsOutboundOptions) { o.HandshakeTimeout = -1 }},
		{"negative-padding", func(o *option.TonglsOutboundOptions) { o.HeaderPaddingMin = -1 }},
		{"reversed-padding", func(o *option.TonglsOutboundOptions) {
			o.HeaderPaddingMin = 512
			o.HeaderPaddingMax = 128
		}},
		{"excess-padding", func(o *option.TonglsOutboundOptions) { o.HeaderPaddingMax = 4097 }},
		{"invalid-initial-padding", func(o *option.TonglsOutboundOptions) { o.InitialPaddingScheme = []string{"stop=-1", "0=16-256"} }},
	} {
		t.Run("outbound/"+test.name, func(t *testing.T) {
			options := privateOutboundOptions(credentials, "127.0.0.1:443")
			test.mutate(&options)
			instance, err := NewOutbound(context.Background(), nil, logger, "invalid", options)
			if err == nil {
				scope := adapter.NewScope(context.Background(), logger)
				defer scope.Close()
				err = instance.(*Outbound).Start(adapter.StartStateInitialize, scope)
			}
			if err == nil {
				t.Fatal("invalid private outbound configuration accepted")
			}
		})
	}
}
