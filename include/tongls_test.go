package include_test

import (
	"context"
	stdjson "encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
	"github.com/sagernet/sing/common/json"
)

func TestTonglsRegistryRoundTrip(t *testing.T) {
	ctx := include.Context(context.Background())
	content := []byte(`{
		"inbounds": [{"type":"tongls","tag":"private-in","listen":"127.0.0.1","listen_port":443,
			"users":[{"name":"test","password":"private-test-credential"}],
			"padding_scheme":["stop=8","0=16-256"],
			"path":"/private","fallback":{"server":"127.0.0.1","server_port":8080},
				"handshake_timeout":"7s","idle_timeout":"2m","max_connections":24,
			"tls":{"enabled":true,"certificate_path":"server.crt","key_path":"server.key"}}],
		"outbounds": [{"type":"tongls","tag":"private-out","server":"example.org","server_port":443,
			"password":"private-test-credential","idle_session_timeout":"45s","min_idle_session":2,
			"initial_padding_scheme":["stop=8","0=16-256"],
			"path":"/private","handshake_timeout":"8s","header_padding_min":64,"header_padding_max":384,
			"tls":{"enabled":true,"server_name":"example.org"}}]
	}`)
	var options option.Options
	if err := json.UnmarshalContext(ctx, content, &options); err != nil {
		t.Fatal(err)
	}
	inbound, ok := options.Inbounds[0].Options.(*option.TonglsInboundOptions)
	if !ok {
		t.Fatalf("inbound options type %T", options.Inbounds[0].Options)
	}
	outbound, ok := options.Outbounds[0].Options.(*option.TonglsOutboundOptions)
	if !ok {
		t.Fatalf("outbound options type %T", options.Outbounds[0].Options)
	}
	if inbound.Path != "/private" || inbound.Fallback == nil || inbound.Fallback.Server != "127.0.0.1" || inbound.Fallback.ServerPort != 8080 || inbound.HandshakeTimeout.Build() != 7*time.Second || inbound.IdleTimeout.Build() != 2*time.Minute || inbound.MaxConnections != 24 {
		t.Fatal("private inbound configuration was not preserved")
	}
	if outbound.Path != "/private" || outbound.HandshakeTimeout.Build() != 8*time.Second || outbound.HeaderPaddingMin != 64 || outbound.HeaderPaddingMax != 384 {
		t.Fatal("private outbound configuration was not preserved")
	}
	if !reflect.DeepEqual([]string(outbound.InitialPaddingScheme), []string{"stop=8", "0=16-256"}) || outbound.IdleSessionTimeout.Build() != 45*time.Second || outbound.MinIdleSession != 2 {
		t.Fatal("initial padding or existing session options were not preserved")
	}
	encoded, err := json.MarshalContext(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	var decoded option.Options
	if err = json.UnmarshalContext(ctx, encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(options.Inbounds, decoded.Inbounds) || !reflect.DeepEqual(options.Outbounds, decoded.Outbounds) {
		t.Fatal("Tongls configuration changed during JSON round trip")
	}
}

func TestTonglsKeepsOrdinaryAnyTLS(t *testing.T) {
	ctx := include.Context(context.Background())
	var options option.Options
	if err := json.UnmarshalContext(ctx, []byte(`{
        "inbounds":[{"type":"anytls","users":[{"name":"test","password":"test"}]}],
        "outbounds":[{"type":"anytls","server":"example.org","server_port":443,"password":"test","tls":{"enabled":true}}]
    }`), &options); err != nil {
		t.Fatal(err)
	}
	if _, ok := options.Inbounds[0].Options.(*option.AnyTLSInboundOptions); !ok {
		t.Fatalf("original inbound options type %T", options.Inbounds[0].Options)
	}
	if _, ok := options.Outbounds[0].Options.(*option.AnyTLSOutboundOptions); !ok {
		t.Fatalf("original outbound options type %T", options.Outbounds[0].Options)
	}
	for _, content := range []string{
		`{"outbounds":[{"type":"anytls","private":{"enabled":true}}]}`,
		`{"inbounds":[{"type":"anytls","path":"/gate"}]}`,
		`{"outbounds":[{"type":"anytls","initial_padding_scheme":["stop=0"]}]}`,
		`{"outbounds":[{"type":"tongls","private":{"enabled":true}}]}`,
		`{"outbounds":[{"type":"tongls","fallback":{"server":"example.org","server_port":80}}]}`,
		`{"inbounds":[{"type":"tongls","header_padding_min":64}]}`,
		`{"outbounds":[{"type":"tongls","initial_padding_scheme":123}]}`,
	} {
		var invalid option.Options
		if err := json.UnmarshalContext(ctx, []byte(content), &invalid); err == nil {
			t.Fatalf("accepted unsupported protocol fields: %s", content)
		}
	}
}

type tonglsSchemaNode struct {
	Ref        string                       `json:"$ref"`
	Const      any                          `json:"const"`
	Properties map[string]*tonglsSchemaNode `json:"properties"`
	OneOf      []*tonglsSchemaNode          `json:"oneOf"`
	AnyOf      []*tonglsSchemaNode          `json:"anyOf"`
	Items      *tonglsSchemaNode            `json:"items"`
	Type       any                          `json:"type"`
}

func TestTonglsGeneratedSchema(t *testing.T) {
	content, err := schema.Generate(include.Context(context.Background()), reflect.TypeFor[option.Options]())
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Defs map[string]*tonglsSchemaNode `json:"$defs"`
	}
	if err = stdjson.Unmarshal(content, &document); err != nil {
		t.Fatal(err)
	}
	resolve := func(node *tonglsSchemaNode) *tonglsSchemaNode {
		for depth := 0; node != nil && node.Ref != "" && depth < 16; depth++ {
			if !strings.HasPrefix(node.Ref, "#/$defs/") {
				t.Fatalf("unexpected schema reference %q", node.Ref)
			}
			node = document.Defs[strings.TrimPrefix(node.Ref, "#/$defs/")]
		}
		return node
	}
	for _, definition := range []string{"Inbound", "Outbound"} {
		root := document.Defs[definition]
		if root == nil {
			t.Fatalf("missing %s definition", definition)
		}
		found, originalFound := 0, 0
		for _, variant := range root.OneOf {
			kind := variant.Properties["type"]
			if kind == nil {
				continue
			}
			if kind.Const == C.TypeAnyTLS {
				originalFound++
				for _, field := range []string{"private", "initial_padding_scheme", "path", "handshake_timeout", "header_padding_min", "fallback"} {
					if variant.Properties[field] != nil {
						t.Errorf("original %s AnyTLS schema acquired Tongls field %s", definition, field)
					}
				}
				continue
			}
			if kind.Const != C.TypeTongls {
				continue
			}
			found++
			if variant.Properties["private"] != nil || variant.Properties["enabled"] != nil {
				t.Errorf("%s Tongls schema retains obsolete mode toggle", definition)
			}
			fields := []string{"path", "handshake_timeout"}
			if definition == "Inbound" {
				fields = append(fields, "fallback", "idle_timeout", "max_connections")
			} else {
				fields = append(fields, "header_padding_min", "header_padding_max")
				initial := resolve(variant.Properties["initial_padding_scheme"])
				if initial == nil {
					t.Fatal("outbound schema omits initial_padding_scheme")
				}
				// Listable strings must retain both supported JSON forms.
				array, scalar := false, false
				for _, form := range initial.AnyOf {
					form = resolve(form)
					if form.Type == "string" {
						scalar = true
					} else if form.Type == "array" && resolve(form.Items).Type == "string" {
						array = true
					}
				}
				if !array || !scalar {
					t.Fatal("initial padding schema must permit a string or array of strings")
				}
			}
			for _, field := range fields {
				if variant.Properties[field] == nil {
					t.Errorf("%s private schema omits %s", definition, field)
				}
			}
		}
		if found != 1 {
			t.Fatalf("%s Tongls variant count = %d", definition, found)
		}
		if originalFound != 1 {
			t.Fatalf("%s original AnyTLS variant count = %d", definition, originalFound)
		}
	}
}
