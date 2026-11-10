package tongls

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/tongls"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.TonglsOutboundOptions](registry, C.TypeTongls, NewOutbound)
}

var (
	_ adapter.OutboundWithMultiplex   = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
	_ adapter.IdleConnectionKeeper    = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	dialer        tls.Dialer
	server        M.Socksaddr
	tlsConfig     tls.Config
	clientOptions tongls.ClientOptions
	client        *tongls.Client
	uotClient     *uot.Client
	logger        log.ContextLogger
	private       *privateOutbound
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TonglsOutboundOptions) (adapter.Outbound, error) {
	var err error
	options.TLS, err = privateClientTLS(options.TLS)
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeTongls, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		server:  options.ServerOptions.Build(),
		logger:  logger,
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}
	if options.DialerOptions.TCPFastOpen {
		return nil, E.New("tcp_fast_open is not supported with Tongls outbound")
	}

	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	outbound.tlsConfig = tlsConfig

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}

	outbound.dialer = tls.NewDialer(outboundDialer, tlsConfig)
	outbound.private, err = newPrivateOutbound(options, options.Password, tlsConfig.ServerName(), options.ServerOptions.Build())
	if err != nil {
		return nil, err
	}
	var initialPadding []byte
	if len(options.InitialPaddingScheme) > 0 {
		initialPadding = []byte(strings.Join(options.InitialPaddingScheme, "\n"))
	} else {
		initialPadding = tongls.TonglsPaddingScheme
	}
	if len(initialPadding) > 0 {
		if err = tongls.ValidateInitialPaddingScheme(initialPadding); err != nil {
			return nil, err
		}
	}

	outbound.clientOptions = tongls.ClientOptions{
		Password:                 options.Password,
		ClientMetadata:           options.ClientMetadata,
		DialOut:                  outbound.dialOut,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(),
		MinIdleSession:           options.MinIdleSession,
		Logger:                   logger,
		InitialPaddingScheme:     initialPadding,
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	client, err := tongls.NewClient(h.clientOptions)
	if err != nil {
		return err
	}
	h.client = client
	scope.Add(client.Close)
	h.uotClient = &uot.Client{
		Dialer:  tonglsDialer(client.DialContext),
		Version: uot.Version,
	}
	return nil
}

type tonglsDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func (d tonglsDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d tonglsDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) dialOut(ctx context.Context) (net.Conn, error) {
	return h.private.dial(ctx, h.dialer, h.server)
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.client.Reset()
}

func (h *Outbound) SetKeepIdleConnections(keep bool) {
	h.client.SetKeepIdleConnections(keep)
}

func (h *Outbound) CloseIdleConnections() {
	h.client.CloseIdleConnections()
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}
