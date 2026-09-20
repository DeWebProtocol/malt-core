package main

import (
	"strings"
	"testing"
)

func TestParseStartupBackend(t *testing.T) {
	for _, backend := range []string{"kzg", "ipa"} {
		t.Run(backend, func(t *testing.T) {
			got, err := parseStartupBackend([]string{backendArgumentPrefix + backend})
			if err != nil {
				t.Fatalf("parseStartupBackend failed: %v", err)
			}
			if got != backend {
				t.Fatalf("backend = %q, want %q", got, backend)
			}
		})
	}
	for _, args := range [][]string{
		nil,
		{"kzg"},
		{backendArgumentPrefix},
		{backendArgumentPrefix + "all"},
		{backendArgumentPrefix + "kzg", backendArgumentPrefix + "ipa"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			if backend, err := parseStartupBackend(args); err == nil {
				t.Fatalf("parseStartupBackend(%q) = %q, want error", args, backend)
			}
		})
	}
}
