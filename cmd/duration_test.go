package cmd

import (
	"fmt"
	"strings"
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
		"8d":                       8 * 24 * time.Hour,
		" 8 D ":                    8 * 24 * time.Hour,
		"1h30m":                    90 * time.Minute,
		"1.5h":                     90 * time.Minute,
		"0":                        0,
		"0d":                       0,
		"0h":                       0,
		"0m":                       0,
		"0s":                       0,
		"2562047h47m16.854775807s": time.Duration(1<<63 - 1),
		"9223372036854775807ns":    time.Duration(1<<63 - 1),
	} {
		t.Run(value, func(t *testing.T) {
			if got, err := parseDuration(value); err != nil || got != want {
				t.Errorf("parseDuration(%q) = %v, %v; want %v", value, got, err, want)
			}
		})
	}
	for _, value := range []string{
		"-1d", "-1h", "-1m", "-1s", "-1ns", "1.5d",
		"-2562047h47m16.854775808s",
		"2562047h47m16.854775808s", "9223372036854775808ns",
	} {
		if _, err := parseDuration(value); err == nil {
			t.Errorf("parseDuration(%q) must remain invalid", value)
		}
	}
}

func TestHealthThresholdsRequirePositiveDurations(t *testing.T) {
	for _, flag := range []string{"--stale-after", "--stale-after-inactive", "--inactive-after"} {
		for _, value := range []string{"0", "0d", "-1h"} {
			t.Run(flag+"/"+value, func(t *testing.T) {
				root := newRootCommand()
				root.SetArgs([]string{"code-scanning", "--repository", "acme/repo", flag, value})
				if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "invalid "+flag) {
					t.Fatalf("%s=%s was accepted: %v", flag, value, err)
				}
			})
		}
	}
}

func TestCacheMaxAgeAllowsZeroButRejectsNegative(t *testing.T) {
	if got, err := parseDuration("0"); err != nil || got != 0 {
		t.Fatalf("zero cache age must retain its documented no-limit meaning: %v, %v", got, err)
	}
	if _, err := parseDuration("-1h"); err == nil {
		t.Fatal("negative cache age must be rejected")
	}
}
