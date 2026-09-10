package cmd

import (
	"fmt"
	"testing"
	"time"
)

func TestParseDurationIntegerBoundaries(t *testing.T) {
	const maxDuration = time.Duration(1<<63 - 1)
	for suffix, unit := range map[string]time.Duration{
		"d": 24 * time.Hour,
		"h": time.Hour,
		"m": time.Minute,
		"s": time.Second,
	} {
		t.Run(suffix, func(t *testing.T) {
			maxAmount := int64(maxDuration / unit)
			valid := fmt.Sprintf("%d%s", maxAmount, suffix)
			want := time.Duration(maxAmount) * unit
			if got, err := parseDuration(valid); err != nil || got != want {
				t.Errorf("parseDuration(%q) = %v, %v; want %v", valid, got, err, want)
			}
			for _, value := range []string{
				fmt.Sprintf("%d%s", maxAmount+1, suffix),
				fmt.Sprintf("%d%s", int64(maxDuration), suffix),
				"999999999999999999999999999999" + suffix,
			} {
				if got, err := parseDuration(value); err == nil {
					t.Errorf("parseDuration(%q) overflowed without an error: %v", value, got)
				}
			}
		})
	}
}

func TestParseDurationPreservesValidForms(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"8d":                        8 * 24 * time.Hour,
		" 8 D ":                     8 * 24 * time.Hour,
		"1h30m":                     90 * time.Minute,
		"1.5h":                      90 * time.Minute,
		"0":                         0,
		"0d":                        0,
		"0h":                        0,
		"0m":                        0,
		"0s":                        0,
		"-1h":                       -time.Hour,
		"2562047h47m16.854775807s":  time.Duration(1<<63 - 1),
		"9223372036854775807ns":     time.Duration(1<<63 - 1),
		"-2562047h47m16.854775808s": time.Duration(-1 << 63),
	} {
		t.Run(value, func(t *testing.T) {
			if got, err := parseDuration(value); err != nil || got != want {
				t.Errorf("parseDuration(%q) = %v, %v; want %v", value, got, err, want)
			}
		})
	}
	for _, value := range []string{"-1d", "1.5d", "2562047h47m16.854775808s", "9223372036854775808ns"} {
		if _, err := parseDuration(value); err == nil {
			t.Errorf("parseDuration(%q) must remain invalid", value)
		}
	}
}
