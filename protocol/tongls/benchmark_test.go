package tongls

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// BenchmarkTonglsCost isolates the additional HTTPS gate cost. Cold
// scenarios explicitly reset both implementations' pools after each operation;
// warm scenarios preserve session reuse after one unmeasured priming stream.
// The target is an in-process echo router, not a remote application server.
func BenchmarkTonglsCost(b *testing.B) {
	credentials := privateCredentials(b)
	for _, private := range []bool{false, true} {
		for _, warm := range []bool{false, true} {
			name := "anytls/cold"
			if private {
				name = "tongls/cold"
			}
			if warm {
				name = name[:len(name)-4] + "warm"
			}
			b.Run(name, func(b *testing.B) {
				b.StopTimer()
				var server *privateTestServer
				var client comparisonClient
				if private {
					server = startPrivateInbound(b, privateEchoRouter(), privateInboundOptions(credentials, "127.0.0.1:1"))
					client, _ = startPrivateOutbound(b, privateOutboundOptions(credentials, server.address))
				} else {
					server = startOrdinaryInbound(b, privateEchoRouter(), credentials)
					client, _ = startOrdinaryOutbound(b, privateOutboundOptions(credentials, server.address))
				}
				payload := bytes.Repeat([]byte{0x5a}, 16*1024)
				received := make([]byte, len(payload))
				if warm {
					privateBenchmarkExchange(b, client, payload, received)
				}
				initialHandshakes := server.handshakes.Load()
				latencies := make([]time.Duration, b.N)
				b.ReportAllocs()
				b.SetBytes(2 * int64(len(payload)))
				b.ResetTimer()
				b.StartTimer()
				for index := 0; index < b.N; index++ {
					latencies[index] = privateBenchmarkExchange(b, client, payload, received)
					if !warm {
						client.InterfaceUpdated(context.Background())
					}
				}
				b.StopTimer()
				slices.Sort(latencies)
				// Some Windows time.Now clocks cannot resolve a warm loopback
				// exchange. Suppress zero percentiles instead of claiming zero
				// latency; testing.B's aggregate ns/op remains the primary metric.
				zeroSamples := 0
				for _, latency := range latencies {
					if latency == 0 {
						zeroSamples++
					}
				}
				if p50 := latencies[(len(latencies)-1)/2]; p50 > 0 {
					b.ReportMetric(float64(p50.Nanoseconds()), "p50-ttfb-ns")
				}
				if p95 := latencies[(len(latencies)-1)*95/100]; p95 > 0 {
					b.ReportMetric(float64(p95.Nanoseconds()), "p95-ttfb-ns")
				}
				b.ReportMetric(float64(zeroSamples)/float64(b.N), "unresolved-ttfb-fraction")
				b.ReportMetric(float64(server.handshakes.Load()-initialHandshakes)/float64(b.N), "TLS-handshakes/op")
			})
		}
	}
}

func privateBenchmarkExchange(b *testing.B, client comparisonClient, payload, received []byte) time.Duration {
	b.Helper()
	started := time.Now()
	conn, err := client.DialContext(context.Background(), "tcp", M.ParseSocksaddr("example.org:443"))
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = conn.Write(payload); err != nil {
		b.Fatal(err)
	}
	if _, err = io.ReadFull(conn, received[:1]); err != nil {
		b.Fatal(err)
	}
	latency := time.Since(started)
	if _, err = io.ReadFull(conn, received[1:]); err != nil {
		b.Fatal(err)
	}
	if !bytes.Equal(payload, received) {
		b.Fatal("echo changed application payload")
	}
	return latency
}
