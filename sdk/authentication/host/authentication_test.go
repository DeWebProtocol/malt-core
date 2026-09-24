package host

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/protocol"
	cid "github.com/ipfs/go-cid"
)

func TestTypedWriterUpdatesCompleteCandidate(t *testing.T) {
	c, err := newComputer("kzg")
	if err != nil {
		t.Fatal(err)
	}
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.KZG4096}, Entries: []engine.Entry{{Label: []byte("key"), Target: cid.MustParse("bafkqaaa")}}}
	encoded, _ := json.Marshal(state)
	base, err := c.PrepareAuthentication(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries = []engine.Entry{}
	encoded, _ = json.Marshal(state)
	next, err := c.UpdateAuthentication(context.Background(), base, encoded)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := protocol.DecodeAuthenticationCandidate(next)
	if err != nil {
		t.Fatal(err)
	}
	original, err := protocol.DecodeAuthenticationCandidate(base)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Root == original.Root || candidate.Previous != original.Root {
		t.Fatal("update lost its base")
	}
	original.State.Entries[0].Target = cid.MustParse("bafkqaaa")
	original.State.Entries[0].Label = []byte("corrupt")
	bad, _ := json.Marshal(original)
	if _, err := c.UpdateAuthentication(context.Background(), bad, encoded); err == nil {
		t.Fatal("corrupt base accepted")
	}
}
