package main

import (
	"encoding/json"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func TestSessionComputerAcceptsConsecutiveBootstrapWritesAcrossBackends(t *testing.T) {
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		t.Run(string(backend), func(t *testing.T) {
			computer, err := newComputer(string(backend))
			if err != nil {
				t.Fatal(err)
			}
			session, err := newSessionComputer(computer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := session.bootstrap(t.Context()); err != nil {
				t.Fatal(err)
			}

			prepareAndAccept := func(operationID, key string) {
				t.Helper()
				after := arcset.NewCASTarget(payloadCID(t, operationID+"-payload"))
				intent := mutation.SemanticIntent{
					Profile:     mutation.SemanticIntentProfile,
					BaseRoot:    session.view.BaseRoot,
					TopOutputID: operationID + "-output",
					Transitions: []mutation.IntentTransition{{
						ID: operationID + "-output", ObjectID: "root", OldRoot: session.view.BaseRoot,
						Kind: arcset.KindMap, Backend: backend,
						Changes: []mutation.IntentChange{{Coordinate: mustMapCoordinate(t, key), After: &after}},
					}},
				}
				wireIntent, err := protocol.NewSemanticIntent(session.view, intent)
				if err != nil {
					t.Fatal(err)
				}
				intentJSON, err := json.Marshal(wireIntent)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := session.prepare(t.Context(), operationID, intentJSON); err != nil {
					t.Fatalf("prepare %s: %v", operationID, err)
				}
				raw, err := session.getPreparedResult(operationID)
				if err != nil {
					t.Fatal(err)
				}
				response, err := protocol.DecodeWriterComputeResult(raw)
				if err != nil {
					t.Fatal(err)
				}
				bundle, err := response.Bundle.Core()
				if err != nil {
					t.Fatal(err)
				}
				digest, err := bundle.Digest()
				if err != nil {
					t.Fatal(err)
				}
				receipt, err := protocol.NewMaterializationReceipt(mutation.MaterializationReceipt{
					Profile:         mutation.MaterializationReceiptProfile,
					OperationID:     operationID,
					BaseRoot:        bundle.View.BaseRoot,
					Candidate:       bundle.Candidate,
					BundleDigest:    digest,
					DurableBoundary: "unit-memory-v1",
				}, bundle)
				if err != nil {
					t.Fatal(err)
				}
				receiptJSON, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				validated, err := validateMaterializationReceipt(raw, receiptJSON)
				if err != nil {
					t.Fatalf("validate receipt %s: %v", operationID, err)
				}
				if validated != bundle.Candidate.String() {
					t.Fatalf("validated root = %s, want %s", validated, bundle.Candidate)
				}
				badReceipt := receipt
				badReceipt.Candidate = bundle.View.BaseRoot.String()
				badReceiptJSON, err := json.Marshal(badReceipt)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := validateMaterializationReceipt(raw, badReceiptJSON); err == nil {
					t.Fatal("stateless validation accepted a mismatched receipt")
				}
				accepted, err := session.acceptReceipt(operationID, receiptJSON)
				if err != nil {
					t.Fatalf("accept %s: %v", operationID, err)
				}
				if accepted != bundle.Candidate.String() {
					t.Fatalf("accepted root = %s, want %s", accepted, bundle.Candidate)
				}
			}

			prepareAndAccept("first-operation", "first")
			prepareAndAccept("second-operation", "second")
			if session.view.Objects[0].Entries.Len() != 2 {
				t.Fatalf("retained root entries = %d, want 2", session.view.Objects[0].Entries.Len())
			}
		})
	}
}

func mustMapCoordinate(t *testing.T, value string) arcset.CanonicalCoordinate {
	t.Helper()
	coordinate, err := arcset.NewMapCoordinate(value)
	if err != nil {
		t.Fatal(err)
	}
	return coordinate
}
