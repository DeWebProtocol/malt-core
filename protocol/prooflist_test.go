package protocol_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestProofListAuthenticationCorpus(t *testing.T) {
	raw, err := os.ReadFile("../conformance/authentication-v5.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			ID           string
			Valid        bool
			Verification json.RawMessage
		}
	}
	if err = json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	verifier, err := builtin.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range corpus.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			input, err := protocol.DecodeAuthenticationVerification(v.Verification)
			if err != nil {
				if v.Valid {
					t.Fatal(err)
				}
				return
			}
			wire, err := protocol.EncodeProofList(input.Request, input.Result)
			if err != nil {
				if v.Valid {
					t.Fatal(err)
				}
				return
			}
			got, err := protocol.DecodeProofList(input.Request, wire)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := authentication.Verify(verifier, input.Request, got)
			if (ok && err == nil) != v.Valid {
				t.Fatalf("valid=%v error=%v", ok, err)
			}
			if !v.Valid {
				return
			}
			golden := map[string]string{
				"profile-1.opaque-label": "876ffe473f3864ba70bd219ccfcf7cc8ae618d3f358c5de284d41533cbbea94a",
				"profile-2.opaque-label": "916b431103414089cbfefb5be4a826cedf17e7363990b03255f140a89a09c3e1",
			}
			if want := golden[v.ID]; want != "" && fmt.Sprintf("%x", sha256.Sum256(wire)) != want {
				t.Fatal("compact bytes differ from the reference encoding")
			}
			wantJSON, _ := json.Marshal(input.Result)
			gotJSON, _ := json.Marshal(got)
			if !bytes.Equal(wantJSON, gotJSON) {
				t.Fatal("compact projection changed typed evidence")
			}
			again, err := protocol.EncodeProofList(input.Request, got)
			if err != nil || !bytes.Equal(again, wire) {
				t.Fatal("noncanonical round trip", err)
			}
			for _, bad := range [][]byte{wire[:len(wire)-1], append(bytes.Clone(wire), 0), append([]byte{wire[0] | 0x80, 0}, wire[1:]...), {2}} {
				if _, err := protocol.DecodeProofList(input.Request, bad); err == nil {
					t.Fatal("accepted malformed framing")
				}
			}
			size := map[string]int{"profile-1.list-range-with-gap": 207, "profile-2.list-range-with-gap": 1679}[v.ID]
			if size != 0 {
				root := cid.MustParse(input.Request.Root)
				step, err := protocol.EncodeBindingProof(root, coordinate.EncodeIndex(0), got.Range.Segments[0])
				if err != nil || len(step) != size {
					t.Fatalf("step bytes=%d want=%d error=%v", len(step), size, err)
				}
				t.Logf("List segment %d B, full range %d B (JSON %d B)", len(step), len(wire), len(wantJSON))
				got.Range.Segments[0].Proof.Nodes[0].Metadata = nil
				if _, err := protocol.EncodeProofList(input.Request, got); err == nil {
					t.Fatal("accepted inconsistent shared metadata")
				}
			}
			if got.Binding != nil && got.Binding.Present {
				n := &got.Binding.Proof.Nodes[0]
				n.Proof[len(n.Proof)-1] ^= 1
				if _, err := protocol.EncodeProofList(input.Request, got); err == nil {
					t.Fatal("accepted inconsistent primitive slot")
				}
			}
		})
	}
}

func TestProofListTraversalSizesAndBinding(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	registry := engine.NewRegistry()
	if err := registry.Register(scheme); err != nil {
		t.Fatal(err)
	}
	e := engine.New(registry)
	target, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}).Sum([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	d := maltcid.RootDescriptor{Layout: maltcid.Map, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.KZG4096}
	for _, depth := range []int{0, 2, 8} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			nodes := memory.NewNodes()
			root := target
			steps := make([][]byte, depth)
			for i := depth - 1; i >= 0; i-- {
				steps[i] = []byte(fmt.Sprintf("entry-%010d", i))
				root, err = e.Build(t.Context(), engine.State{Descriptor: d, Entries: []engine.Entry{{Label: steps[i], Target: root}}}, nodes)
				if err != nil {
					t.Fatal(err)
				}
			}
			if depth == 0 {
				root, err = e.Build(t.Context(), engine.State{Descriptor: d}, nodes)
				if err != nil {
					t.Fatal(err)
				}
			}
			q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: root.String(), Steps: steps, Operation: "resolve"}
			r, err := authentication.Execute(t.Context(), e, q, nodes)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := protocol.EncodeProofList(q, r)
			if err != nil {
				t.Fatal(err)
			}
			want := map[int]int{0: 1, 2: 192, 8: 828}[depth]
			if len(wire) != want {
				t.Fatalf("wire %d, want %d", len(wire), want)
			}
			var old bytes.Buffer
			if err := json.NewEncoder(&old).Encode(r); err != nil {
				t.Fatal(err)
			}
			t.Logf("HTTP body compact=%d B JSON=%d B", len(wire), old.Len())
			got, err := protocol.DecodeProofList(q, wire)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := authentication.Verify(e, q, got); !ok || err != nil {
				t.Fatal(ok, err)
			}
			if depth > 0 {
				q.Steps[0] = []byte("different")
				other, err := protocol.DecodeProofList(q, wire)
				if err == nil {
					if ok, _ := authentication.Verify(e, q, other); ok {
						t.Fatal("accepted evidence for another label")
					}
				}
			}
		})
	}
	// Two distinct keys diverge in the third radix-4096 digit. A third label
	// follows the same route to a foreign leaf, exercising nonempty absence.
	d.DerivationProfile = uint8(derivation.Direct)
	label, other := make([]byte, 32), make([]byte, 32)
	other[3] = 0x80
	nodes := memory.NewNodes()
	root, err := e.Build(t.Context(), engine.State{Descriptor: d, Entries: []engine.Entry{{Label: label, Target: target}, {Label: other, Target: target}}}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	for _, present := range []bool{true, false} {
		selected := bytes.Clone(label)
		if !present {
			selected[31] = 1
		}
		q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: root.String(), Operation: "binding", Label: &selected}
		r, err := authentication.Execute(t.Context(), e, q, nodes)
		if err != nil {
			t.Fatal(err)
		}
		if r.Binding.Present != present || len(r.Binding.Proof.Nodes) != 3 {
			t.Fatal("unexpected multilevel fixture")
		}
		wire, err := protocol.EncodeProofList(q, r)
		if err != nil {
			t.Fatal(err)
		}
		got, err := protocol.DecodeProofList(q, wire)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := authentication.Verify(e, q, got); !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
}
