package tonglshttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testPassword = "8c55907b0dad9321b69fd87bac81d8534ee57b45bfc154d097d47842bedac8c7"

func testBackend(t testing.TB) *httptest.Server {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Website", "real-backend")
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = fmt.Fprintf(w, "website|%s|%s|%s|%s", r.Method, r.URL.RequestURI(), r.Host, r.Header.Get("Authorization"))
	}))
	t.Cleanup(backend.Close)
	return backend
}

func testGate(t testing.TB, callback func(context.Context, net.Conn, string)) *httptest.Server {
	t.Helper()
	backend := testBackend(t)
	backendURL, _ := url.Parse(backend.URL)
	h, err := NewHandler([]User{{Name: "test", Password: testPassword}}, "/private", backendURL, callback)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.(io.Closer).Close() })
	return testTLSServer(t, h)
}

func testTLSServer(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.MaxHeaderBytes = 8192
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func dialTestTLS(t testing.TB, server *httptest.Server) *tls.Conn {
	t.Helper()
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	config.MinVersion, config.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	config.NextProtos = []string{"http/1.1"}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", server.Listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func signedRequest(t testing.TB, conn *tls.Conn, host, path, password string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState()
	exported, err := state.ExportKeyingMaterial(exporterLabel, nil, sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	key := sha256.Sum256([]byte(password))
	proof := makeProof(key, exported, request.Method, request.Host, request.URL.RequestURI())
	request.Header.Set("Proxy-Authorization", encodeAuthorization(key, proof))
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", Protocol)
	return request
}

func TestUpgradeRoundTripAndContextDetachment(t *testing.T) {
	seen := make(chan string, 1)
	server := testGate(t, func(_ context.Context, conn net.Conn, user string) {
		seen <- user
		_, _ = io.Copy(conn, conn)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := Client(ctx, dialTestTLS(t, server), "website.test", "/private", testPassword, 16, 32)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	if _, err = conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	var payload [5]byte
	if _, err = io.ReadFull(conn, payload[:]); err != nil || string(payload[:]) != "hello" {
		t.Fatalf("echo = %q, %v", payload, err)
	}
	select {
	case name := <-seen:
		if name != "test" {
			t.Fatalf("user = %q", name)
		}
	case <-time.After(time.Second):
		t.Fatal("missing upgrade callback")
	}
}

func TestUpgradePreservesPipelinedClientBytes(t *testing.T) {
	server := testGate(t, func(_ context.Context, conn net.Conn, _ string) {
		payload := make([]byte, 12)
		if _, err := io.ReadFull(conn, payload); err == nil {
			_, _ = conn.Write(payload)
		}
	})
	conn := dialTestTLS(t, server)
	request := signedRequest(t, conn, "website.test", "/private", testPassword)
	var wire bytes.Buffer
	if err := request.Write(&wire); err != nil {
		t.Fatal(err)
	}
	wire.WriteString("inner-anytls")
	if _, err := conn.Write(wire.Bytes()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response = %v, %v", response, err)
	}
	var payload [12]byte
	if _, err = io.ReadFull(reader, payload[:]); err != nil || string(payload[:]) != "inner-anytls" {
		t.Fatalf("pipelined echo = %q, %v", payload, err)
	}
}

func TestClientPreservesPipelinedServerBytes(t *testing.T) {
	server := testTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: " + Protocol + "\r\n\r\ninner-anytls")
		_ = rw.Flush()
	}))
	conn, err := Client(context.Background(), dialTestTLS(t, server), "website.test", "/private", testPassword, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var payload [12]byte
	if _, err = io.ReadFull(conn, payload[:]); err != nil || string(payload[:]) != "inner-anytls" {
		t.Fatalf("buffered response = %q, %v", payload, err)
	}
}

func TestOrdinaryAndUnauthorizedRequestsReachWebsite(t *testing.T) {
	var upgrades atomic.Int32
	server := testGate(t, func(_ context.Context, _ net.Conn, _ string) { upgrades.Add(1) })
	for _, test := range []struct {
		name       string
		method     string
		path       string
		auth       string
		upgrade    bool
		expectAuth string
	}{
		{name: "ordinary_get", method: "GET", path: "/"},
		{name: "unknown_path", method: "GET", path: "/missing"},
		{name: "ordinary_head", method: "HEAD", path: "/"},
		{name: "missing_auth", method: "GET", path: "/private", upgrade: true},
		{name: "wrong_auth", method: "GET", path: "/private", auth: "Tongls " + base64.StdEncoding.EncodeToString(make([]byte, 32)), upgrade: true},
		{name: "malformed_auth", method: "GET", path: "/private", auth: "Tongls invalid", upgrade: true},
		{name: "ordinary_website_auth", method: "GET", path: "/", auth: "Basic dGVzdDpwYXNz", expectAuth: "Basic dGVzdDpwYXNz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := dialTestTLS(t, server)
			request, _ := http.NewRequest(test.method, "https://website.test"+test.path, nil)
			request.Close = true
			if strings.HasPrefix(test.auth, "Tongls") {
				request.Header.Set("Proxy-Authorization", test.auth)
			} else {
				request.Header.Set("Authorization", test.auth)
			}
			if test.upgrade {
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", Protocol)
			}
			if err := request.Write(conn); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.Header.Get("X-Website") != "real-backend" || response.StatusCode == http.StatusSwitchingProtocols {
				t.Fatalf("response did not come from website: %v", response)
			}
			if test.method != "HEAD" {
				expected := fmt.Sprintf("website|%s|%s|website.test|%s", test.method, test.path, test.expectAuth)
				if string(body) != expected {
					t.Fatalf("body = %q, expected %q", body, expected)
				}
			}
		})
	}
	if upgrades.Load() != 0 {
		t.Fatalf("unauthorized upgrade count = %d", upgrades.Load())
	}
}

func TestReplayAndRequestTamperingRejected(t *testing.T) {
	var upgrades atomic.Int32
	server := testGate(t, func(_ context.Context, _ net.Conn, _ string) { upgrades.Add(1) })
	first := dialTestTLS(t, server)
	original := signedRequest(t, first, "website.test", "/private", testPassword)
	proof := original.Header.Get("Proxy-Authorization")
	if err := original.Write(first); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(first), original)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("initial proof rejected: %v, %v", response, err)
	}
	first.Close()
	for _, kind := range []string{"replay", "host", "path", "password", "duplicate_auth", "previous_auth_scheme", "previous_upgrade"} {
		t.Run(kind, func(t *testing.T) {
			conn := dialTestTLS(t, server)
			request := signedRequest(t, conn, "website.test", "/private", testPassword)
			switch kind {
			case "replay":
				request.Header.Set("Proxy-Authorization", proof)
			case "host":
				request.Host = "different.test"
			case "path":
				wrong := signedRequest(t, conn, "website.test", "/other", testPassword)
				request.Header.Set("Proxy-Authorization", wrong.Header.Get("Proxy-Authorization"))
			case "password":
				wrong := signedRequest(t, conn, "website.test", "/private", "wrong password")
				request.Header.Set("Proxy-Authorization", wrong.Header.Get("Proxy-Authorization"))
			case "duplicate_auth":
				request.Header.Add("Proxy-Authorization", proof)
			case "previous_auth_scheme":
				request.Header.Set("Proxy-Authorization", strings.Replace(request.Header.Get("Proxy-Authorization"), "Tongls ", "AnyTLS ", 1))
			case "previous_upgrade":
				request.Header.Set("Upgrade", "anytls-private-v1")
			}
			if err := request.Write(conn); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK || response.Header.Get("X-Website") != "real-backend" {
				t.Fatalf("invalid proof did not receive website response: %v", response)
			}
		})
	}
	if upgrades.Load() != 1 {
		t.Fatalf("upgrade count = %d", upgrades.Load())
	}
}

func TestHTTP2UsesOrdinaryWebsite(t *testing.T) {
	server := testGate(t, func(_ context.Context, _ net.Conn, _ string) { t.Error("HTTP/2 unexpectedly upgraded") })
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/private", nil)
	request.Header.Set("Proxy-Authorization", "Tongls invalid")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.Header.Get("X-Website") != "real-backend" {
		t.Fatalf("unexpected HTTP/2 response: %v", response)
	}
	body, _ := io.ReadAll(response.Body)
	if strings.Contains(string(body), "Tongls") {
		t.Fatalf("private authorization leaked to fallback: %q", body)
	}
}

func TestPrivateProbeMatchesOrdinaryReverseProxyResponse(t *testing.T) {
	backend := testBackend(t)
	backendURL, _ := url.Parse(backend.URL)
	h, err := NewHandler([]User{{Name: "test", Password: testPassword}}, "/private", backendURL, func(context.Context, net.Conn, string) { t.Error("unexpected upgrade") })
	if err != nil {
		t.Fatal(err)
	}
	defer h.(io.Closer).Close()
	gate := testTLSServer(t, h)
	baseline := testTLSServer(t, httputil.NewSingleHostReverseProxy(backendURL))
	for _, wire := range []string{
		"GET / HTTP/1.1\r\nHost: website.test\r\nConnection: close\r\n\r\n",
		"HEAD /missing HTTP/1.1\r\nHost: website.test\r\nConnection: close\r\n\r\n",
		"GET /private HTTP/1.1\r\nHost: website.test\r\nConnection: Upgrade, close\r\nUpgrade: tongls-v1\r\n\r\n",
		"GET /private HTTP/1.1\r\nHost: website.test\r\nConnection: Upgrade, close\r\nUpgrade: tongls-v1\r\nProxy-Authorization: Tongls AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
		"GET / HTTP/1.0\r\n\r\n",
		"THIS IS NOT HTTP\r\n\r\n",
	} {
		var responses [2]string
		for index, server := range []*httptest.Server{gate, baseline} {
			conn := dialTestTLS(t, server)
			if _, err := io.WriteString(conn, wire); err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(conn)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(string(payload), "\r\n")
			for index, line := range lines {
				if strings.HasPrefix(line, "Date: ") {
					lines[index] = "Date: <normalized>"
				}
			}
			responses[index] = strings.Join(lines, "\r\n")
		}
		if responses[0] != responses[1] {
			t.Fatalf("probe response differs for %q:\ngate=%q\nnormal=%q", wire, responses[0], responses[1])
		}
	}
}

func TestClientCancellationAndHeaderLimit(t *testing.T) {
	t.Run("cancel", func(t *testing.T) {
		server := testTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
		conn := dialTestTLS(t, server)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		started := time.Now()
		if stream, err := Client(ctx, conn, "website.test", "/private", testPassword, 1, 1); err == nil || stream != nil {
			t.Fatal("canceled upgrade succeeded")
		}
		if time.Since(started) > time.Second {
			t.Fatal("cancellation did not promptly interrupt IO")
		}
	})
	t.Run("oversized_headers", func(t *testing.T) {
		server := testTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nX-Large: " + strings.Repeat("x", 2*maxHeaderBytes) + "\r\n\r\n")
			_ = rw.Flush()
		}))
		if _, err := Client(context.Background(), dialTestTLS(t, server), "website.test", "/private", testPassword, 1, 1); err == nil {
			t.Fatal("oversized response headers accepted")
		}
	})
	t.Run("wrong_password", func(t *testing.T) {
		server := testGate(t, func(context.Context, net.Conn, string) { t.Error("wrong password upgraded") })
		if _, err := Client(context.Background(), dialTestTLS(t, server), "website.test", "/private", "wrong", 1, 1); !errors.Is(err, ErrRejected) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestValidationAndPadding(t *testing.T) {
	for _, path := range []string{"relative", "//host", "/x?query", "/x#fragment", "/a b", "/bad\r\n"} {
		if _, err := NormalizePath(path); err == nil {
			t.Errorf("accepted invalid path %q", path)
		}
	}
	for _, path := range []string{"", "/", "/private", "/a%2Fb"} {
		if _, err := NormalizePath(path); err != nil {
			t.Errorf("rejected path %q: %v", path, err)
		}
	}
	for _, pair := range [][2]int{{-1, 10}, {30, 20}, {0, 4097}} {
		if _, _, err := NormalizePadding(pair[0], pair[1]); err == nil {
			t.Errorf("accepted padding bounds %v", pair)
		}
	}
	for index := 0; index < 100; index++ {
		padding, err := randomPadding(16, 32)
		if err != nil || len(padding) < 16 || len(padding) > 32 || strings.ContainsAny(padding, " \r\n\t") {
			t.Fatalf("invalid padding %q: %v", padding, err)
		}
	}
	backend, _ := url.Parse("http://127.0.0.1:8080")
	callback := func(context.Context, net.Conn, string) {}
	for _, users := range [][]User{nil, {{Name: "", Password: "x"}}, {{Name: "x", Password: ""}}, {{Name: "x", Password: "a"}, {Name: "x", Password: "b"}}, {{Name: "x", Password: "a"}, {Name: "y", Password: "a"}}} {
		if _, err := NewHandler(users, "/", backend, callback); err == nil {
			t.Errorf("accepted invalid users")
		}
	}
	for _, rawURL := range []string{"https://example.org", "http://user:pass@example.org", "http://example.org/?q=x", "http://example.org/#x"} {
		invalid, _ := url.Parse(rawURL)
		if _, err := NewHandler([]User{{Name: "test", Password: testPassword}}, "/", invalid, callback); err == nil {
			t.Errorf("accepted invalid fallback %q", rawURL)
		}
	}
}

func TestCredentialSelectorSeparatesUsers(t *testing.T) {
	backend := testBackend(t)
	backendURL, _ := url.Parse(backend.URL)
	seen := make(chan string, 2)
	users := []User{{Name: "first", Password: "first-long-password"}, {Name: "second", Password: "second-long-password"}}
	h, err := NewHandler(users, "/private", backendURL, func(_ context.Context, _ net.Conn, name string) { seen <- name })
	if err != nil {
		t.Fatal(err)
	}
	defer h.(io.Closer).Close()
	server := testTLSServer(t, h)
	for _, user := range users {
		conn, err := Client(context.Background(), dialTestTLS(t, server), "website.test", "/private", user.Password, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
		select {
		case name := <-seen:
			if name != user.Name {
				t.Fatalf("selected %q, expected %q", name, user.Name)
			}
		case <-time.After(time.Second):
			t.Fatal("missing selected user")
		}
	}
}

// This measures only the private proof check after TLS/HTTP parsing, not packet
// timing, HTTP latency or resistance to active probing. User count should not
// multiply request-proof HMAC work.
func BenchmarkAuthenticate(b *testing.B) {
	server := testTLSServer(b, http.NotFoundHandler())
	conn := dialTestTLS(b, server)
	state := conn.ConnectionState()
	exported, err := state.ExportKeyingMaterial(exporterLabel, nil, sha256.Size)
	if err != nil {
		b.Fatal(err)
	}
	backend, _ := url.Parse("http://127.0.0.1:1")
	for _, count := range []int{1, 1024} {
		users := make([]User, count)
		for index := range users {
			users[index] = User{Name: fmt.Sprintf("user-%d", index), Password: fmt.Sprintf("benchmark-password-%d", index)}
		}
		httpHandler, err := NewHandler(users, "/private", backend, func(context.Context, net.Conn, string) {})
		if err != nil {
			b.Fatal(err)
		}
		h := httpHandler.(*handler)
		defer h.Close()
		key := sha256.Sum256([]byte(users[count-1].Password))
		proof := makeProof(key, exported, http.MethodGet, "website.test", "/private")
		for _, kind := range []string{"valid", "known_bad", "unknown", "no_auth"} {
			b.Run(fmt.Sprintf("users=%d/%s", count, kind), func(b *testing.B) {
				request := &http.Request{Method: http.MethodGet, Host: "website.test", RequestURI: "/private", ProtoMajor: 1, ProtoMinor: 1, TLS: &state, Header: make(http.Header)}
				request.Header.Set("Connection", "Upgrade")
				request.Header.Set("Upgrade", Protocol)
				authorization := encodeAuthorization(key, proof)
				if kind == "known_bad" {
					bad := proof
					bad[0] ^= 1
					authorization = encodeAuthorization(key, bad)
				} else if kind == "unknown" {
					unknown := sha256.Sum256([]byte("unknown benchmark credential"))
					authorization = encodeAuthorization(unknown, makeProof(unknown, exported, http.MethodGet, "website.test", "/private"))
				}
				if kind != "no_auth" {
					request.Header.Set("Proxy-Authorization", authorization)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					_, accepted := h.authenticate(request)
					if accepted != (kind == "valid") {
						b.Fatal("incorrect authentication decision")
					}
				}
			})
		}
	}
}

func FuzzAuthorization(f *testing.F) {
	f.Add("Tongls " + base64.StdEncoding.EncodeToString(make([]byte, authSize)))
	f.Add("Tongls invalid")
	f.Add("Basic abc")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 32*1024 {
			return
		}
		proof, ok := decodeAuthorization(value)
		if ok {
			encoded := "Tongls " + base64.StdEncoding.EncodeToString(proof[:])
			parsed, accepted := decodeAuthorization(encoded)
			if !accepted || parsed != proof {
				t.Fatal("accepted proof does not round trip")
			}
		}
	})
}

func FuzzPath(f *testing.F) {
	f.Add("/private")
	f.Add("/a%2Fb")
	f.Add("//host/")
	f.Fuzz(func(t *testing.T, value string) {
		normalized, err := NormalizePath(value)
		if err == nil {
			again, err := NormalizePath(normalized)
			if err != nil || normalized != again {
				t.Fatal("normalized path is not stable")
			}
		}
	})
}
