package conformancegen

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mapradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/conformance"
	"github.com/dewebprotocol/malt-core/execution"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// GenerateMapProof builds the frozen membership/non-membership corpus. It
// uses the reference prover only to generate untrusted results; corpus
// consumers verify the serialized envelopes independently.
func GenerateMapProof() ([]byte, error) {
	var vectors []conformance.MapProofVector
	for _, backend := range []maltcid.BackendKind{maltcid.BackendKindKZG, maltcid.BackendKindIPA} {
		generated, err := generateMapProofBackend(backend)
		if err != nil {
			return nil, err
		}
		vectors = append(vectors, generated...)
	}
	slices.SortFunc(vectors, func(left, right conformance.MapProofVector) int {
		if left.ID < right.ID {
			return -1
		}
		if left.ID > right.ID {
			return 1
		}
		return 0
	})
	corpus := conformance.MapProofCorpus{SchemaVersion: conformance.MapProofV1, Vectors: vectors}
	if err := corpus.Validate(); err != nil {
		return nil, fmt.Errorf("validate generated Map-proof corpus: %w", err)
	}
	data, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal generated Map-proof corpus: %w", err)
	}
	return append(data, '\n'), nil
}

func generateMapProofBackend(backend maltcid.BackendKind) ([]conformance.MapProofVector, error) {
	ctx := context.Background()
	scheme, err := mapProofScheme(backend)
	if err != nil {
		return nil, err
	}
	scope := "map-proof-conformance-v1-" + string(backend)
	semantic, err := mapradix.NewMap(scheme, materialmemory.New(true))
	if err != nil {
		return nil, fmt.Errorf("create %s Map semantic: %w", backend, err)
	}
	presentTarget, err := rawCID("map-proof-present-" + string(backend))
	if err != nil {
		return nil, err
	}
	root, err := semantic.Commit(ctx, scope, mapping.NewViewFrom(map[string]cid.Cid{"present": presentTarget}))
	if err != nil {
		return nil, fmt.Errorf("commit %s Map fixture: %w", backend, err)
	}
	otherTarget, err := rawCID("map-proof-other-" + string(backend))
	if err != nil {
		return nil, err
	}
	otherRoot, err := semantic.Commit(ctx, scope, mapping.NewViewFrom(map[string]cid.Cid{"other": otherTarget}))
	if err != nil {
		return nil, fmt.Errorf("commit alternate %s Map fixture: %w", backend, err)
	}
	executor, err := execution.NewExecutor(execution.Options{Scope: scope, Maps: semantic})
	if err != nil {
		return nil, err
	}

	present, err := mapProofVerification(ctx, executor, root, "present")
	if err != nil {
		return nil, err
	}
	absent, err := mapProofVerification(ctx, executor, root, "missing")
	if err != nil {
		return nil, err
	}
	prefix := "map-proof." + string(backend) + "."
	vectors := make([]conformance.MapProofVector, 0, 7)
	appendVector := func(id, category string, value any, valid bool) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		vectors = append(vectors, conformance.MapProofVector{
			ID: id, Operation: conformance.OperationMapProof, Backend: string(backend), Category: category,
			Verification: raw, Expected: conformance.Expected{Valid: valid},
		})
		return nil
	}
	if err := appendVector(prefix+"membership.accept", "membership", present, true); err != nil {
		return nil, err
	}
	if err := appendVector(prefix+"absence.accept", "absence", absent, true); err != nil {
		return nil, err
	}

	proofTamper, err := cloneMapProof(absent)
	if err != nil {
		return nil, err
	}
	if err := tamperMapProof(&proofTamper); err != nil {
		return nil, err
	}
	if err := appendVector(prefix+"proof-tamper.reject", "tamper", proofTamper, false); err != nil {
		return nil, err
	}

	crossRoot, err := cloneMapProof(absent)
	if err != nil {
		return nil, err
	}
	crossRoot.Request.Root = otherRoot.String()
	crossRoot.Result.ProofList.Root = otherRoot
	for index := range crossRoot.Result.ProofList.Steps {
		crossRoot.Result.ProofList.Steps[index].From = otherRoot
	}
	if err := appendVector(prefix+"cross-root.reject", "cross_root", crossRoot, false); err != nil {
		return nil, err
	}

	wrongKey, err := cloneMapProof(absent)
	if err != nil {
		return nil, err
	}
	wrongKey.Request.Key = []string{"another-missing"}
	if err := appendVector(prefix+"wrong-key.reject", "wrong_key", wrongKey, false); err != nil {
		return nil, err
	}

	targetTamper, err := cloneMapProof(present)
	if err != nil {
		return nil, err
	}
	targetTamper.Result.Target = otherTarget.String()
	if err := appendVector(prefix+"target-tamper.reject", "target_tamper", targetTamper, false); err != nil {
		return nil, err
	}

	strictRaw, err := json.Marshal(absent)
	if err != nil {
		return nil, err
	}
	var strict map[string]any
	if err := json.Unmarshal(strictRaw, &strict); err != nil {
		return nil, err
	}
	strict["unknown"] = true
	if err := appendVector(prefix+"unknown-field.reject", "strict_json", strict, false); err != nil {
		return nil, err
	}
	return vectors, nil
}

func mapProofScheme(backend maltcid.BackendKind) (commitment.IndexCommitment, error) {
	switch backend {
	case maltcid.BackendKindKZG:
		return kzg.NewScheme()
	case maltcid.BackendKindIPA:
		return ipa.NewScheme()
	default:
		return nil, fmt.Errorf("unsupported Map-proof conformance backend %q", backend)
	}
}

func mapProofVerification(ctx context.Context, executor *execution.Executor, root cid.Cid, key string) (protocol.MapProofVerification, error) {
	request := malt.MapProofRequest{Root: root, Key: arcset.CanonicalizePath(key)}
	result, err := executor.ProveMap(ctx, request)
	if err != nil {
		return protocol.MapProofVerification{}, err
	}
	wireRequest, err := protocol.NewMapProofRequest(request)
	if err != nil {
		return protocol.MapProofVerification{}, err
	}
	wireResult, err := protocol.NewMapProofResult(result)
	if err != nil {
		return protocol.MapProofVerification{}, err
	}
	return protocol.MapProofVerification{Request: wireRequest, Result: wireResult}, nil
}

func cloneMapProof(value protocol.MapProofVerification) (protocol.MapProofVerification, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return protocol.MapProofVerification{}, err
	}
	var cloned protocol.MapProofVerification
	if err := json.Unmarshal(data, &cloned); err != nil {
		return protocol.MapProofVerification{}, err
	}
	return cloned, nil
}

func tamperMapProof(value *protocol.MapProofVerification) error {
	if value == nil || len(value.Result.ProofList.Steps) == 0 {
		return fmt.Errorf("Map-proof conformance fixture has no proof step")
	}
	var envelope struct {
		Steps []struct {
			Slot  []byte `json:"slot,omitempty"`
			Proof []byte `json:"proof"`
		} `json:"steps"`
		Bucket json.RawMessage `json:"bucket,omitempty"`
	}
	if err := json.Unmarshal(value.Result.ProofList.Steps[0].Proof, &envelope); err != nil {
		return err
	}
	if len(envelope.Steps) == 0 || len(envelope.Steps[0].Proof) < 4 {
		return fmt.Errorf("Map-proof conformance fixture has no mutable primitive proof")
	}
	envelope.Steps[0].Proof[len(envelope.Steps[0].Proof)-1] ^= 0x01
	tampered, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	value.Result.ProofList.Steps[0].Proof = tampered
	return nil
}
