package conformance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/conformance"
	"github.com/dewebprotocol/malt-core/internal/conformancegen"
	"github.com/dewebprotocol/malt-core/protocol"
	clientwriter "github.com/dewebprotocol/malt-core/sdk/writer"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func TestClientRootCorpus(t *testing.T) {
	corpus, err := conformance.LoadClientRoot()
	if err != nil {
		t.Fatalf("LoadClientRoot: %v", err)
	}
	for _, vector := range corpus.Vectors {
		vector := vector
		t.Run(vector.ID, func(t *testing.T) {
			bundle, materialization, nextView, accepted := computeClientRootVector(t.Context(), vector)
			if accepted != vector.Expected.Valid {
				t.Fatalf("accepted = %t, want %t", accepted, vector.Expected.Valid)
			}
			if !accepted {
				return
			}
			if !reflect.DeepEqual(bundle, *vector.Expected.Bundle) {
				t.Fatalf("bundle mismatch\n got: %#v\nwant: %#v", bundle, *vector.Expected.Bundle)
			}
			if !reflect.DeepEqual(materialization, *vector.Expected.Materialization) {
				t.Fatalf("materialization mismatch\n got: %#v\nwant: %#v", materialization, *vector.Expected.Materialization)
			}
			if !reflect.DeepEqual(nextView, *vector.Expected.NextView) {
				t.Fatalf("next view mismatch\n got: %#v\nwant: %#v", nextView, *vector.Expected.NextView)
			}
			coreBundle, err := bundle.Core()
			if err != nil {
				t.Fatalf("bundle Core: %v", err)
			}
			if _, err := vector.Expected.Receipt.Core(coreBundle); err != nil {
				t.Fatalf("expected receipt does not bind computed bundle: %v", err)
			}
		})
	}
}

func TestClientRootCorpusIsGenerated(t *testing.T) {
	want, err := conformance.ClientRootBytes()
	if err != nil {
		t.Fatalf("ClientRootBytes: %v", err)
	}
	got, err := conformancegen.GenerateClientRoot()
	if err != nil {
		t.Fatalf("GenerateClientRoot: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("checked-in client-root vectors.json is stale; run go generate ./conformance")
	}
}

func TestClientRootSchemasAreJSON(t *testing.T) {
	for _, name := range []string{"corpus.schema.json", "vector.schema.json"} {
		data, err := conformance.ClientRootSchema(name)
		if err != nil {
			t.Fatalf("ClientRootSchema(%q): %v", name, err)
		}
		if !json.Valid(data) {
			t.Fatalf("ClientRootSchema(%q) is not valid JSON", name)
		}
	}
}

func TestClientRootCorpusDigestIsImmutable(t *testing.T) {
	data, err := conformance.ClientRootBytes()
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "4346f06abcc1ed2bebfd1a24d56fc400dca56468c15613bd052034c0b4babc50" {
		t.Fatalf("client-root v1 corpus digest changed: %s", got)
	}
}

func TestClientRootCoverageMatrix(t *testing.T) {
	corpus, err := conformance.LoadClientRoot()
	if err != nil {
		t.Fatalf("LoadClientRoot: %v", err)
	}
	type coverageKey struct {
		backend  string
		category string
		valid    bool
	}
	covered := make(map[coverageKey]bool, len(corpus.Vectors))
	for _, vector := range corpus.Vectors {
		covered[coverageKey{vector.Backend, vector.Category, vector.Expected.Valid}] = true
	}
	for _, backend := range []string{conformance.BackendKZG, conformance.BackendIPA} {
		for _, required := range []coverageKey{
			{backend, "replace", true},
			{backend, "stale_base", false},
			{backend, "view_tamper", false},
			{backend, "wrong_backend", false},
			{backend, "strict_json", false},
		} {
			if !covered[required] {
				t.Errorf("missing coverage: backend=%s category=%s valid=%t", required.backend, required.category, required.valid)
			}
		}
	}
}

func TestClientRootViewTamperReachesRootRecomputation(t *testing.T) {
	corpus, err := conformance.LoadClientRoot()
	if err != nil {
		t.Fatalf("LoadClientRoot: %v", err)
	}
	tested := 0
	for _, vector := range corpus.Vectors {
		if vector.Category != "view_tamper" {
			continue
		}
		vector := vector
		tested++
		t.Run(vector.ID, func(t *testing.T) {
			wireView, err := protocol.DecodeUpdateView(vector.UpdateView)
			if err != nil {
				t.Fatalf("tampered view must pass strict wire decoding: %v", err)
			}
			view, err := wireView.Core()
			if err != nil {
				t.Fatalf("tampered view must pass semantic normalization: %v", err)
			}
			wireIntent, err := protocol.DecodeSemanticIntent(vector.SemanticIntent, view)
			if err != nil {
				t.Fatalf("tampered intent must validate against the declared view: %v", err)
			}
			if _, err := wireIntent.Core(view); err != nil {
				t.Fatalf("tampered intent must pass semantic normalization: %v", err)
			}
			backend := maltcid.BackendKind(vector.Backend)
			scheme, err := clientRootTestScheme(backend)
			if err != nil {
				t.Fatal(err)
			}
			runtime, err := clientwriter.NewRuntime(
				materialmemory.New(true),
				map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme},
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.VerifyUpdateView(t.Context(), view); err == nil {
				t.Fatal("VerifyUpdateView accepted entries under a different valid typed root")
			} else if !strings.Contains(err.Error(), "recomputed root") {
				t.Fatalf("VerifyUpdateView rejected before root recomputation: %v", err)
			}
		})
	}
	if tested == 0 {
		t.Fatal("client-root corpus has no view_tamper vectors")
	}
}

func computeClientRootVector(ctx context.Context, vector conformance.ClientRootVector) (
	protocol.ClientRootBundle,
	protocol.ClientRootMaterialization,
	protocol.UpdateView,
	bool,
) {
	wireView, err := protocol.DecodeUpdateView(vector.UpdateView)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	view, err := wireView.Core()
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	wireIntent, err := protocol.DecodeSemanticIntent(vector.SemanticIntent, view)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	intent, err := wireIntent.Core(view)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	backend := maltcid.BackendKind(vector.Backend)
	scheme, err := clientRootTestScheme(backend)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	runtime, err := clientwriter.NewRuntime(
		materialmemory.New(true),
		map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme},
	)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	verified, err := runtime.VerifyUpdateView(ctx, view)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	result, err := runtime.ComputeBundle(ctx, vector.OperationID, verified, intent)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	bundle, err := protocol.NewClientRootBundle(result.Bundle)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	materialization, err := protocol.NewClientRootMaterialization(result.Bundle, result.Materialization)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	nextView, err := protocol.NewUpdateView(result.NextView)
	if err != nil {
		return protocol.ClientRootBundle{}, protocol.ClientRootMaterialization{}, protocol.UpdateView{}, false
	}
	return bundle, materialization, nextView, true
}

func clientRootTestScheme(backend maltcid.BackendKind) (commitment.IndexCommitment, error) {
	switch backend {
	case maltcid.BackendKindKZG:
		return kzg.NewScheme()
	case maltcid.BackendKindIPA:
		return ipa.NewScheme()
	default:
		return nil, fmt.Errorf("unsupported client-root backend %q", backend)
	}
}
