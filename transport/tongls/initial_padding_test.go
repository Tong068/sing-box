package tongls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	upstream "github.com/sagernet/sing-anytls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestInitialPaddingValidation(t *testing.T) {
	for _, scheme := range [][]byte{
		DefaultPaddingScheme,
		TonglsPaddingScheme,
		[]byte("stop=0"),
		[]byte("stop=1\n0=65535-65535"),
		[]byte("stop=2\n1=7-100,c,100-200\n"),
	} {
		if err := ValidateInitialPaddingScheme(scheme); err != nil {
			t.Fatalf("valid scheme rejected: %q: %v", scheme, err)
		}
	}
	for _, scheme := range []string{
		"", "stop=-1", "stop=1025", "stop=01", "stop=8\nstop=9", "0=30-30",
		"stop=8\nwrong=1-2", "stop=8\n0=65536-65536", "stop=8\n0=c",
		"stop=8\n0=30-30,31-31", "stop=8\n0=0-30", "stop=8\n0=20-10",
		"stop=8\n0=20", "stop=8\n0=20-30\n0=10-20", "stop=8\n8=20-30",
		"stop=8\n1=1000000-1000000,1000000-1000000",
		"stop=8\n1=" + strings.Repeat("c,", 64) + "1-2",
		"stop=8\n1=" + strings.Repeat("x", 16*1024),
	} {
		if err := ValidateInitialPaddingScheme([]byte(scheme)); !errors.Is(err, ErrPaddingScheme) {
			t.Errorf("invalid scheme accepted or wrong error: %q: %v", scheme, err)
		}
		if scheme != "" {
			if client, err := NewClient(ClientOptions{InitialPaddingScheme: []byte(scheme)}); err == nil {
				client.Close()
				t.Errorf("NewClient accepted invalid scheme: %q", scheme)
			}
		}
	}
}

func TestInitialPaddingCopiesInputAndDoesNotChangeDefaults(t *testing.T) {
	before := append([]byte(nil), DefaultPaddingScheme...)
	raw := []byte("stop=1\n0=42-42")
	client, err := NewClient(ClientOptions{InitialPaddingScheme: raw})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for index := range raw {
		raw[index] = 'x'
	}
	if value := client.padding.Load(); value.GenerateHandshakePaddingSize() != 42 || string(value.rawScheme) != "stop=1\n0=42-42" {
		t.Fatal("client retained mutable caller padding bytes")
	}
	if !bytes.Equal(before, DefaultPaddingScheme) {
		t.Fatal("custom profile modified upstream defaults")
	}
	defaults, err := NewClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer defaults.Close()
	if defaults.padding.Load().GenerateHandshakePaddingSize() != 30 {
		t.Fatal("empty option no longer uses upstream default")
	}
}

func FuzzInitialPaddingScheme(f *testing.F) {
	for _, raw := range [][]byte{DefaultPaddingScheme, TonglsPaddingScheme, []byte("stop=0"), []byte("stop=1\n0=65535-65535"), []byte("stop=-1")} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if ValidateInitialPaddingScheme(raw) != nil {
			return
		}
		factory, err := newPaddingFactory(raw)
		if err != nil {
			t.Fatalf("validated initial scheme failed legacy parsing: %v", err)
		}
		if padding := factory.GenerateHandshakePaddingSize(); padding < 0 || padding > maxFrameSize {
			t.Fatalf("validated initial scheme generates invalid auth size: %d", padding)
		}
	})
}

func TestFirstAuthenticationWriteLengths(t *testing.T) {
	for _, test := range []struct {
		name   string
		scheme []byte
		min    int
		max    int
	}{
		{"upstream_default", nil, 64, 64},
		{"private_initial", TonglsPaddingScheme, 50, 289},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := make(map[int]bool)
			var captured *authenticationCaptureConn
			client, err := NewClient(ClientOptions{
				Password:             "independent-interop-test-password",
				InitialPaddingScheme: test.scheme,
				DialOut: func(context.Context) (net.Conn, error) {
					captured = newAuthenticationCaptureConn()
					return captured, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for range 128 {
				created, err := client.createSession(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				packet := captured.firstWrite()
				created.Close()
				if len(packet) < test.min || len(packet) > test.max {
					t.Fatalf("authentication length %d outside %d..%d", len(packet), test.min, test.max)
				}
				if padding := int(binary.BigEndian.Uint16(packet[32:34])); padding != len(packet)-34 {
					t.Fatalf("padding length field %d does not match write length %d", padding, len(packet))
				}
				expected := sha256.Sum256([]byte("independent-interop-test-password"))
				if !bytes.Equal(packet[:32], expected[:]) {
					t.Fatal("authentication layout changed")
				}
				observed[len(packet)] = true
			}
			if test.min != test.max && len(observed) < 2 {
				t.Fatal("randomized profile produced only one observed length in 128 samples")
			}
		})
	}
}

func TestAuthenticationRejectsOversizedServerUpdatedPadding(t *testing.T) {
	var captured *authenticationCaptureConn
	client, err := NewClient(ClientOptions{DialOut: func(context.Context) (net.Conn, error) {
		captured = newAuthenticationCaptureConn()
		return captured, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// The legacy server-update parser permits this value. It must never wrap
	// when encoded into the authentication request's uint16 padding length.
	updated, err := newPaddingFactory([]byte("stop=1\n0=65536-65536"))
	if err != nil {
		t.Fatal(err)
	}
	client.padding.Store(updated)
	if _, err = client.createSession(context.Background()); !errors.Is(err, ErrPaddingScheme) {
		t.Fatalf("oversized authentication accepted: %v", err)
	}
	if len(captured.firstWrite()) != 0 {
		t.Fatal("wrote an authentication request with a truncated length")
	}
	select {
	case <-captured.done:
	default:
		t.Fatal("connection not closed on rejected padding")
	}
}

type interopClient interface {
	DialContext(context.Context, M.Socksaddr) (net.Conn, error)
	Close() error
}

type connectionHandler func(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc)

func (h connectionHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h(ctx, conn, source, destination, onClose)
}

func TestUpstreamInteroperability(t *testing.T) {
	for _, localClient := range []bool{false, true} {
		t.Run(fmt.Sprintf("local_client=%v", localClient), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			const password = "interop-password-with-sufficient-test-length"
			payload := []byte("test anytls wire interoperability")
			handlerErrors := make(chan error, 4)
			handler := connectionHandler(func(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
				defer conn.Close()
				if destination != M.ParseSocksaddr("example.org:443") {
					handlerErrors <- fmt.Errorf("unexpected target %s", destination)
					return
				}
				if err := N.ReportConnHandshakeSuccess(conn, conn); err != nil {
					handlerErrors <- err
					return
				}
				buffer := make([]byte, len(payload))
				_, err := io.ReadFull(conn, buffer)
				if err == nil && !bytes.Equal(buffer, payload) {
					err = fmt.Errorf("incorrect request payload")
				}
				if err == nil {
					_, err = conn.Write(buffer)
				}
				handlerErrors <- err
			})
			var serve func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error
			serverScheme := []byte("stop=1\n0=77-77")
			if localClient {
				server, err := upstream.NewService(password, upstream.ServiceOptions{Handler: handler, PaddingScheme: serverScheme})
				if err != nil {
					t.Fatal(err)
				}
				serve = server.NewConnection
			} else {
				server, err := NewService(password, ServiceOptions{Handler: handler, PaddingScheme: TonglsPaddingScheme})
				if err != nil {
					t.Fatal(err)
				}
				serve = server.NewConnection
			}
			var workers sync.WaitGroup
			dialOut := func(context.Context) (net.Conn, error) {
				clientConn, serverConn := net.Pipe()
				deadline, _ := ctx.Deadline()
				clientConn.SetDeadline(deadline)
				serverConn.SetDeadline(deadline)
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer serverConn.Close()
					_ = serve(ctx, serverConn, M.ParseSocksaddr("127.0.0.1:12345"), nil)
				}()
				return clientConn, nil
			}
			var client interopClient
			var err error
			if localClient {
				client, err = NewClient(ClientOptions{Password: password, DialOut: dialOut, InitialPaddingScheme: TonglsPaddingScheme})
			} else {
				client, err = upstream.NewClient(upstream.ClientOptions{Password: password, DialOut: dialOut})
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				client.Close()
				workers.Wait()
			})
			for range 2 {
				conn, err := client.DialContext(ctx, M.ParseSocksaddr("example.org:443"))
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = conn.Write(payload); err != nil {
					conn.Close()
					t.Fatal(err)
				}
				response := make([]byte, len(payload))
				_, err = io.ReadFull(conn, response)
				conn.Close()
				if err != nil || !bytes.Equal(response, payload) {
					t.Fatalf("incorrect echoed payload, error: %v", err)
				}
				select {
				case err = <-handlerErrors:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if localClient && client.(*Client).padding.Load().GenerateHandshakePaddingSize() != 77 {
				t.Fatal("original server padding update did not replace custom initial scheme")
			}
		})
	}
}

type authenticationCaptureConn struct {
	mu    sync.Mutex
	first []byte
	once  sync.Once
	done  chan struct{}
}

func newAuthenticationCaptureConn() *authenticationCaptureConn {
	return &authenticationCaptureConn{done: make(chan struct{})}
}

func (c *authenticationCaptureConn) firstWrite() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.first...)
}

func (c *authenticationCaptureConn) Read([]byte) (int, error) {
	<-c.done
	return 0, io.EOF
}

func (c *authenticationCaptureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.first == nil {
		c.first = append([]byte(nil), p...)
	}
	return len(p), nil
}

func (c *authenticationCaptureConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (*authenticationCaptureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*authenticationCaptureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*authenticationCaptureConn) SetDeadline(time.Time) error      { return nil }
func (*authenticationCaptureConn) SetReadDeadline(time.Time) error  { return nil }
func (*authenticationCaptureConn) SetWriteDeadline(time.Time) error { return nil }
