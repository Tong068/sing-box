package tongls

import (
	"fmt"
	"strconv"
	"strings"
)

// TonglsPaddingScheme retains the upstream profile except for its first
// authentication write. The inherited range sampler is upper-exclusive, so
// 0=16-256 produces 16..255 padding bytes (50..289 authentication bytes).
// This removes a fixed default length; it is not evidence of traffic camouflage.
var TonglsPaddingScheme = []byte(`stop=8
0=16-256
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`)

// ValidateInitialPaddingScheme validates the explicit initial-client option.
// Unlike the legacy parser it rejects ignored, duplicate or out-of-range input.
// Server-supplied updates retain upstream parsing and negotiation behavior.
func ValidateInitialPaddingScheme(raw []byte) error {
	if len(raw) == 0 || len(raw) > 16*1024 {
		return fmt.Errorf("%w: initial scheme must contain 1..16384 bytes", ErrPaddingScheme)
	}
	values := make(map[string]string)
	for line := range strings.SplitSeq(string(raw), "\n") {
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || value == "" {
			return fmt.Errorf("%w: malformed initial padding line", ErrPaddingScheme)
		}
		if _, exists := values[key]; exists {
			return fmt.Errorf("%w: duplicate initial padding key %q", ErrPaddingScheme, key)
		}
		values[key] = value
	}
	stopText, exists := values["stop"]
	if !exists {
		return fmt.Errorf("%w: missing initial padding stop", ErrPaddingScheme)
	}
	stop, err := strconv.ParseUint(stopText, 10, 32)
	if err != nil || stop > 1024 || strconv.FormatUint(stop, 10) != stopText {
		return fmt.Errorf("%w: initial padding stop must be 0..1024", ErrPaddingScheme)
	}
	for key, value := range values {
		if key == "stop" {
			continue
		}
		packet, err := strconv.ParseUint(key, 10, 32)
		if err != nil || strconv.FormatUint(packet, 10) != key || packet != 0 && packet >= stop {
			return fmt.Errorf("%w: invalid initial padding record %q", ErrPaddingScheme, key)
		}
		items := strings.Split(value, ",")
		if len(items) > 64 || packet == 0 && len(items) != 1 {
			return fmt.Errorf("%w: invalid initial padding range count", ErrPaddingScheme)
		}
		total := uint64(0)
		for _, item := range items {
			if item == "c" && packet != 0 {
				continue
			}
			minText, maxText, found := strings.Cut(item, "-")
			minimum, minErr := strconv.ParseUint(minText, 10, 32)
			maximum, maxErr := strconv.ParseUint(maxText, 10, 32)
			if !found || minErr != nil || maxErr != nil || minimum == 0 || minimum > maximum || maximum > maxPaddingSize || strconv.FormatUint(minimum, 10) != minText || strconv.FormatUint(maximum, 10) != maxText {
				return fmt.Errorf("%w: invalid initial padding range in record %s", ErrPaddingScheme, key)
			}
			if packet == 0 && maximum > maxFrameSize {
				return fmt.Errorf("%w: authentication padding must fit uint16", ErrPaddingScheme)
			}
			total += maximum
			if total > maxPaddingSize {
				return fmt.Errorf("%w: initial padding record exceeds 1 MiB", ErrPaddingScheme)
			}
		}
	}
	return nil
}
