package option

import "github.com/sagernet/sing/common/json/badoption"

// Tongls keeps AnyTLS streams behind its own authenticated HTTPS entry.
// It is a separate protocol type and never changes ordinary AnyTLS options.
type TonglsInboundOptions struct {
	ListenOptions
	InboundTLSOptionsContainer
	Users            []TonglsUser               `json:"users,omitempty"`
	PaddingScheme    badoption.Listable[string] `json:"padding_scheme,omitempty"`
	Path             string                     `json:"path,omitempty"`
	Fallback         *ServerOptions             `json:"fallback,omitempty"`
	HandshakeTimeout badoption.Duration         `json:"handshake_timeout,omitempty"`
	IdleTimeout      badoption.Duration         `json:"idle_timeout,omitempty"`
	MaxConnections   int                        `json:"max_connections,omitempty"`
}

type TonglsUser struct {
	Name     string `json:"name,omitempty"`
	Password string `json:"password,omitempty"`
}

type TonglsOutboundOptions struct {
	DialerOptions
	ServerOptions
	OutboundTLSOptionsContainer
	Password                 string                     `json:"password,omitempty"`
	IdleSessionCheckInterval badoption.Duration         `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       badoption.Duration         `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int                        `json:"min_idle_session,omitempty"`
	ClientMetadata           string                     `json:"client_metadata,omitempty"`
	InitialPaddingScheme     badoption.Listable[string] `json:"initial_padding_scheme,omitempty"`
	Path                     string                     `json:"path,omitempty"`
	HandshakeTimeout         badoption.Duration         `json:"handshake_timeout,omitempty"`
	HeaderPaddingMin         int                        `json:"header_padding_min,omitempty"`
	HeaderPaddingMax         int                        `json:"header_padding_max,omitempty"`
}
