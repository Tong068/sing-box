package tongls

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/tonglshttp"
	M "github.com/sagernet/sing/common/metadata"
)

func privateDuration(value, defaultValue time.Duration) (time.Duration, error) {
	if value < 0 {
		return 0, fmt.Errorf("tongls timeout must be positive")
	}
	if value == 0 {
		return defaultValue, nil
	}
	return value, nil
}

func privateServerTLS(options *option.InboundTLSOptions) (*option.InboundTLSOptions, error) {
	if options == nil || !options.Enabled {
		return nil, fmt.Errorf("tongls requires TLS")
	}
	copy := *options
	if copy.Reality != nil && copy.Reality.Enabled || copy.KernelRx || copy.KernelTx || copy.ClientAuthentication != 0 || copy.Insecure {
		return nil, fmt.Errorf("tongls requires standard certificate TLS without Reality, kTLS, insecure or client certificate authentication")
	}
	if copy.MinVersion != "" && copy.MinVersion != "1.3" || copy.MaxVersion != "" && copy.MaxVersion != "1.3" {
		return nil, fmt.Errorf("tongls requires TLS 1.3")
	}
	for _, protocol := range copy.ALPN {
		if protocol != "h2" && protocol != "http/1.1" {
			return nil, fmt.Errorf("tongls HTTPS listener only supports HTTP ALPN")
		}
	}
	copy.MinVersion, copy.MaxVersion = "1.3", "1.3"
	copy.ALPN = []string{"h2", "http/1.1"}
	return &copy, nil
}

func privateClientTLS(options *option.OutboundTLSOptions) (*option.OutboundTLSOptions, error) {
	if options == nil || !options.Enabled {
		return nil, fmt.Errorf("tongls requires TLS")
	}
	copy := *options
	if copy.Insecure || copy.DisableSNI || len(copy.CertificateSHA256) > 0 || len(copy.CertificatePublicKeySHA256) > 0 {
		return nil, fmt.Errorf("tongls requires certificate chain and hostname verification; use certificate or certificate_path for a private CA")
	}
	if copy.Engine != "" && copy.Engine != "go" || copy.UTLS != nil && copy.UTLS.Enabled || copy.Reality != nil && copy.Reality.Enabled || copy.KernelTx || copy.KernelRx || copy.Fragment || copy.RecordFragment || copy.Spoof != "" {
		return nil, fmt.Errorf("tongls v1 requires the standard Go TLS engine without uTLS, Reality, kTLS, fragmentation or spoofing")
	}
	if copy.MinVersion != "" && copy.MinVersion != "1.3" || copy.MaxVersion != "" && copy.MaxVersion != "1.3" {
		return nil, fmt.Errorf("tongls requires TLS 1.3")
	}
	if len(copy.ALPN) != 0 && (len(copy.ALPN) != 1 || copy.ALPN[0] != "http/1.1") {
		return nil, fmt.Errorf("tongls upgrade requires http/1.1 ALPN")
	}
	copy.MinVersion, copy.MaxVersion = "1.3", "1.3"
	copy.ALPN = []string{"http/1.1"}
	return &copy, nil
}

type privateOutbound struct {
	path, host, password string
	timeout              time.Duration
	paddingMin           int
	paddingMax           int
}

func newPrivateOutbound(options option.TonglsOutboundOptions, password, serverName string, server M.Socksaddr) (*privateOutbound, error) {
	if password == "" {
		return nil, fmt.Errorf("tongls requires a nonempty password")
	}
	if !server.IsValid() || server.Port == 0 || serverName == "" {
		return nil, fmt.Errorf("tongls requires a valid server address and port")
	}
	path, err := tonglshttp.NormalizePath(options.Path)
	if err != nil {
		return nil, err
	}
	timeout, err := privateDuration(options.HandshakeTimeout.Build(), 10*time.Second)
	if err != nil {
		return nil, err
	}
	paddingMin, paddingMax, err := tonglshttp.NormalizePadding(options.HeaderPaddingMin, options.HeaderPaddingMax)
	if err != nil {
		return nil, err
	}
	host := serverName
	if server.Port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(int(server.Port)))
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return &privateOutbound{path: path, host: host, password: password, timeout: timeout, paddingMin: paddingMin, paddingMax: paddingMax}, nil
}

func (p *privateOutbound) dial(ctx context.Context, dialer tls.Dialer, server M.Socksaddr) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(adapter.ContextForMultiplexSession(ctx), p.timeout)
	defer cancel()
	conn, err := dialer.DialTLSContext(ctx, server)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	upgraded, err := tonglshttp.Client(ctx, conn, p.host, p.path, p.password, p.paddingMin, p.paddingMax)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err = upgraded.SetDeadline(time.Time{}); err != nil {
		upgraded.Close()
		return nil, err
	}
	return upgraded, nil
}
