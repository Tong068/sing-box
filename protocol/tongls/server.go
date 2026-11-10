package tongls

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	stdtls "crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	stdlog "log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/tonglshttp"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

// Private mode exposes an actual HTTP server before authentication, rather than
// a byte-prefix demultiplexer pretending that an incomplete request is AnyTLS.
type privateInbound struct {
	ctx       context.Context
	owner     *Inbound
	handler   http.Handler
	server    *http.Server
	listener  net.Listener
	handshake time.Duration
	idle      time.Duration
	limit     int
	mu        sync.Mutex
	closed    bool
	active    map[*privateConn]struct{}
}

func newPrivateInbound(ctx context.Context, owner *Inbound, options option.TonglsInboundOptions, users []option.TonglsUser) (*privateInbound, error) {
	if options.Fallback == nil || !options.Fallback.Build().IsValid() || options.Fallback.ServerPort == 0 {
		return nil, fmt.Errorf("tongls requires a fixed plaintext HTTP fallback server and port")
	}
	if len(users) == 0 || len(users) > 1024 {
		return nil, fmt.Errorf("tongls requires between 1 and 1024 users")
	}
	handshake, err := privateDuration(options.HandshakeTimeout.Build(), 10*time.Second)
	if err != nil {
		return nil, err
	}
	idle, err := privateDuration(options.IdleTimeout.Build(), 5*time.Minute)
	if err != nil {
		return nil, err
	}
	limit := options.MaxConnections
	if limit == 0 {
		limit = 1024
	}
	if limit < 1 || limit > 65536 {
		return nil, fmt.Errorf("tongls max_connections must be between 1 and 65536")
	}
	p := &privateInbound{ctx: ctx, owner: owner, handshake: handshake, idle: idle, limit: limit, active: make(map[*privateConn]struct{})}
	fallbackURL := &url.URL{Scheme: "http", Host: options.Fallback.Build().String()}
	httpUsers := make([]tonglshttp.User, len(users))
	innerKeys := make(map[string][sha256.Size]byte, len(users))
	for index, user := range users {
		httpUsers[index] = tonglshttp.User{Name: user.Name, Password: user.Password}
		innerKeys[user.Name] = sha256.Sum256([]byte(user.Password))
	}
	p.handler, err = tonglshttp.NewHandler(httpUsers, options.Path, fallbackURL, func(ctx context.Context, conn net.Conn, name string) {
		// Keep the established AnyTLS auth/frames and its session reuse. The
		// private gate already authenticated this TLS connection before any
		// AnyTLS-specific input or response can reach an unauthenticated peer.
		defer conn.Close()
		// The upstream AnyTLS service classifies its first Read as one auth
		// prologue. Once the HTTPS gate has verified the full channel-bound
		// proof, it is safe to collect a fragmented inner prologue under a
		// deadline. Doing this before the gate would create observable waits
		// for ordinary short HTTP requests; it deliberately happens after it.
		if err := conn.SetReadDeadline(time.Now().Add(p.handshake)); err != nil {
			return
		}
		var header [34]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		expected := innerKeys[name]
		if subtle.ConstantTimeCompare(header[:sha256.Size], expected[:]) != 1 {
			return
		}
		paddingLength := int(binary.BigEndian.Uint16(header[32:]))
		prologue := make([]byte, len(header)+paddingLength)
		copy(prologue, header[:])
		if _, err := io.ReadFull(conn, prologue[len(header):]); err != nil {
			return
		}
		if err := conn.SetReadDeadline(time.Time{}); err != nil {
			return
		}
		cached := bufio.NewCachedConn(conn, buf.As(prologue).ToOwned())
		defer cached.Close()
		owner.logger.DebugContext(ctx, "[", name, "] Tongls HTTPS upgrade authenticated")
		if serveErr := owner.service.NewConnection(ctx, cached, M.SocksaddrFromNet(conn.RemoteAddr()), nil); serveErr != nil {
			owner.logger.DebugContext(ctx, "Tongls session closed: ", serveErr)
		}
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *privateInbound) start(scope *adapter.Scope) error {
	if closer, ok := p.handler.(io.Closer); ok {
		scope.Add(closer.Close)
	}
	scope.Add(p.close)
	rawListener, err := p.owner.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(p.owner.listener.Close)
	p.listener = &privateListener{Listener: rawListener, owner: p}
	config, err := p.owner.tlsConfig.STDConfig()
	if err != nil {
		return err
	}
	config = config.Clone()
	// The common TLS configuration's GetConfigForClient already fetches the
	// latest certificate configuration under its reload lock. Preserve that
	// callback rather than reading STDConfig concurrently on every handshake.
	p.server = &http.Server{
		Handler: p.handler, TLSConfig: config,
		ReadHeaderTimeout: p.handshake, IdleTimeout: p.idle, MaxHeaderBytes: 8192,
		ErrorLog:    stdlog.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return p.ctx },
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			if tracked := trackedPrivateConn(conn); tracked != nil {
				return tracked.context(ctx)
			}
			return ctx
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateActive {
				if tracked := trackedPrivateConn(conn); tracked != nil {
					tracked.established()
				}
			}
		},
	}
	scope.Add(p.server.Close)
	go func() {
		if serveErr := p.server.ServeTLS(p.listener, "", ""); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
			p.owner.logger.Error("Tongls HTTPS listener: ", serveErr)
		}
	}()
	return nil
}

func (p *privateInbound) close() error {
	p.mu.Lock()
	p.closed = true
	connections := make([]*privateConn, 0, len(p.active))
	for conn := range p.active {
		connections = append(connections, conn)
	}
	p.mu.Unlock()
	// http.Server.Close deliberately excludes hijacked connections. These are
	// tracked independently so a private AnyTLS session cannot survive shutdown.
	for _, conn := range connections {
		conn.Close()
	}
	return nil
}

type privateListener struct {
	net.Listener
	owner *privateInbound
}

func (l *privateListener) Accept() (net.Conn, error) {
	for {
		raw, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		p := l.owner
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			raw.Close()
			return nil, net.ErrClosed
		}
		if len(p.active) >= p.limit {
			p.mu.Unlock()
			raw.Close()
			continue
		}
		conn := &privateConn{Conn: raw, owner: p, firstDeadline: time.Now().Add(p.handshake), idleDeadline: time.Now().Add(p.idle)}
		p.active[conn] = struct{}{}
		p.mu.Unlock()
		if err = conn.SetDeadline(time.Time{}); err != nil {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// This wrapper remains beneath TLS and the HTTP hijacker. HTTP/AnyTLS callers
// may clear their own deadlines, but cannot clear the configured idle bound.
type privateConn struct {
	net.Conn
	owner         *privateInbound
	mu            sync.Mutex
	closed        bool
	cancel        context.CancelFunc
	firstDeadline time.Time
	idleDeadline  time.Time
	readDeadline  time.Time
	writeDeadline time.Time
}

func trackedPrivateConn(conn net.Conn) *privateConn {
	if tlsConn, ok := conn.(*stdtls.Conn); ok {
		conn = tlsConn.NetConn()
	}
	tracked, _ := conn.(*privateConn)
	return tracked
}

func (c *privateConn) context(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	closed := c.closed
	c.cancel = cancel
	c.mu.Unlock()
	if closed {
		cancel()
	}
	return ctx
}

func privateEarlier(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}

func (c *privateConn) deadlinesLocked() error {
	capDeadline := privateEarlier(c.firstDeadline, c.idleDeadline)
	if err := c.Conn.SetReadDeadline(privateEarlier(c.readDeadline, capDeadline)); err != nil {
		return err
	}
	return c.Conn.SetWriteDeadline(privateEarlier(c.writeDeadline, capDeadline))
}

func (c *privateConn) established() {
	c.mu.Lock()
	c.firstDeadline = time.Time{}
	c.idleDeadline = time.Now().Add(c.owner.idle)
	err := c.deadlinesLocked()
	c.mu.Unlock()
	if err != nil {
		c.Close()
	}
}

func (c *privateConn) touch() {
	c.mu.Lock()
	c.idleDeadline = time.Now().Add(c.owner.idle)
	err := c.deadlinesLocked()
	c.mu.Unlock()
	if err != nil {
		c.Close()
	}
}

func (c *privateConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *privateConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *privateConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline, c.writeDeadline = deadline, deadline
	return c.deadlinesLocked()
}

func (c *privateConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = deadline
	return c.deadlinesLocked()
}

func (c *privateConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = deadline
	return c.deadlinesLocked()
}

func (c *privateConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	cancel := c.cancel
	c.mu.Unlock()
	err := c.Conn.Close()
	if cancel != nil {
		cancel()
	}
	c.owner.mu.Lock()
	delete(c.owner.active, c)
	c.owner.mu.Unlock()
	return err
}
