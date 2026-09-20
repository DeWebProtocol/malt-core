package nodegeometry

import (
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	"testing"
)

func TestForBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		kind  maltcid.BackendKind
		width int
	}{
		{kind: maltcid.BackendKindIPA, width: IPANodeWidth},
		{kind: maltcid.BackendKindKZG, width: KZGNodeWidth},
	}
	for _, test := range tests {
		geometry, err := ForBackend(test.kind)
		if err != nil {
			t.Fatalf("ForBackend(%q): %v", test.kind, err)
		}
		if got := geometry.NodeWidth(); got != test.width {
			t.Fatalf("ForBackend(%q).NodeWidth() = %d, want %d", test.kind, got, test.width)
		}
	}
	if _, err := ForBackend(maltcid.BackendKindUnknown); err == nil {
		t.Fatal("ForBackend accepted an unknown backend")
	}
}
