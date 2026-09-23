package authentication_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestBatchVerifiesCandidatesAndBindsExactReceipt(t *testing.T) {
	e := pathEngine(t)
	d := maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}
	base, err := authentication.Prepare(t.Context(), e, engine.State{Descriptor: d})
	if err != nil {
		t.Fatal(err)
	}
	child, err := authentication.Prepare(t.Context(), e, engine.State{Descriptor: d, Entries: []engine.Entry{{Label: []byte("@payload"), Target: cid.MustParse("bafkqaaa")}}})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := authentication.PrepareUpdate(t.Context(), e, base, engine.State{Descriptor: d, Entries: []engine.Entry{{Label: []byte("child"), Target: cid.MustParse(child.Root)}}})
	if err != nil {
		t.Fatal(err)
	}
	batch := protocol.AuthenticationBatch{Profile: protocol.AuthenticationBatchProfile, TransactionID: "write-1", Base: base.Root, Root: parent.Root, Candidates: []protocol.AuthenticationCandidate{child, parent}}
	if err := authentication.ValidateBatch(t.Context(), e, batch); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := protocol.DecodeAuthenticationBatch(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := decoded.Digest()
	if err != nil {
		t.Fatal(err)
	}
	receipt := protocol.AuthenticationReceipt{Profile: protocol.AuthenticationReceiptProfile, TransactionID: batch.TransactionID, Base: batch.Base, Root: batch.Root, Digest: digest, DurableBoundary: "test-store:commit-1"}
	if err := receipt.Validate(batch); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*protocol.AuthenticationReceipt){
		func(r *protocol.AuthenticationReceipt) { r.TransactionID = "write-2" },
		func(r *protocol.AuthenticationReceipt) { r.Base = child.Root },
		func(r *protocol.AuthenticationReceipt) { r.Root = child.Root },
		func(r *protocol.AuthenticationReceipt) { r.Digest = strings.Repeat("0", 64) },
		func(r *protocol.AuthenticationReceipt) { r.DurableBoundary = " " },
		func(r *protocol.AuthenticationReceipt) { r.Profile = "malt.materialization-receipt/v2" },
	} {
		bad := receipt
		change(&bad)
		if err := bad.Validate(batch); err == nil {
			t.Fatal("substituted receipt accepted")
		}
	}
	for _, old := range []string{"malt.client-root-bundle/v2", "malt.update-view/v1"} {
		if _, err := protocol.DecodeAuthenticationBatch([]byte(strings.Replace(string(raw), protocol.AuthenticationBatchProfile, old, 1))); err == nil {
			t.Fatal("retired profile accepted")
		}
	}
	for _, data := range []string{
		strings.Replace(string(raw), `"profile":`, `"Profile":`, 1),
		strings.Replace(string(raw), `"transaction_id":`, `"unknown":`, 1),
		string(raw) + `{}`,
	} {
		if _, err := protocol.DecodeAuthenticationBatch([]byte(data)); err == nil {
			t.Fatal("ambiguous batch JSON accepted")
		}
	}
	bad, err := protocol.DecodeAuthenticationBatch(raw)
	if err != nil {
		t.Fatal(err)
	}
	bad.Candidates[0].State.Entries[0].Target = cid.MustParse(base.Root)
	if err := authentication.ValidateBatch(t.Context(), e, bad); err == nil {
		t.Fatal("candidate state substituted without changing its Root")
	}
	bad = decoded
	bad.Candidates = []protocol.AuthenticationCandidate{parent, child}
	bad.Root = child.Root
	if err := bad.Validate(); err == nil {
		t.Fatal("forward dependency accepted")
	}
	bad = decoded
	bad.Candidates = append(append([]protocol.AuthenticationCandidate(nil), decoded.Candidates...), parent)
	if err := bad.Validate(); err == nil {
		t.Fatal("duplicate Root accepted")
	}
}

// No-op results remain valid portable candidates, including after an earlier
// real update. Batch and receipt checks must agree with both writer APIs.
func TestNoOpCandidatesKeepLineageAndMaterialize(t *testing.T) {
	e := pathEngine(t)
	state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: maltcid.IPA256}}
	initial, err := authentication.Prepare(t.Context(), e, state)
	if err != nil {
		t.Fatal(err)
	}
	state.Entries = []engine.Entry{{Label: []byte("file"), Target: cid.MustParse("bafkqaaa")}}
	changed, err := authentication.PrepareUpdate(t.Context(), e, initial, state)
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []protocol.AuthenticationCandidate{initial, changed} {
		t.Run(base.Root, func(t *testing.T) {
			complete, err := authentication.PrepareUpdate(t.Context(), e, base, base.State)
			if err != nil {
				t.Fatal(err)
			}
			session, err := authentication.NewSession(e, authentication.SessionLimits{})
			if err != nil {
				t.Fatal(err)
			}
			handle, err := session.Import(t.Context(), base)
			if err != nil {
				t.Fatal(err)
			}
			next, err := session.Apply(t.Context(), handle.ID, authentication.Delta{})
			if err != nil {
				t.Fatal(err)
			}
			retained, err := session.Export(t.Context(), next.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range []protocol.AuthenticationCandidate{complete, retained} {
				if candidate.Root != base.Root || candidate.Previous != base.Previous {
					t.Fatal("no-op changed Root or lineage")
				}
				batch := protocol.AuthenticationBatch{Profile: protocol.AuthenticationBatchProfile, TransactionID: "no-op", Base: base.Root, Root: candidate.Root, Candidates: []protocol.AuthenticationCandidate{candidate}}
				if err := authentication.ValidateBatch(t.Context(), e, batch); err != nil {
					t.Fatal(err)
				}
				digest, err := batch.Digest()
				if err != nil {
					t.Fatal(err)
				}
				receipt := protocol.AuthenticationReceipt{Profile: protocol.AuthenticationReceiptProfile, TransactionID: batch.TransactionID, Base: batch.Base, Root: batch.Root, Digest: digest, DurableBoundary: "test-store:no-op"}
				if err := receipt.Validate(batch); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
