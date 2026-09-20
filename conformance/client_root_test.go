package conformance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
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
	cid "github.com/ipfs/go-cid"
)

func TestClientRootCorpus(t *testing.T) {
	testClientRootVersions(t, func(t *testing.T, corpus conformance.ClientRootCorpus) {
		for _, vector := range corpus.Vectors {
			vector := vector
			t.Run(vector.ID, func(t *testing.T) {
				bundle, materialization, nextView, accepted := computeClientRootVector(t.Context(), vector, corpus.SchemaVersion)
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
				expectedVersion := maltcid.RootVersion
				expectedBaseVersion := maltcid.RootVersion
				candidate, err := cid.Decode(bundle.Candidate)
				if err != nil || maltcid.VersionIDOf(candidate) != expectedVersion {
					t.Fatalf("candidate must be a V%d Root: %s (%v)", expectedVersion, bundle.Candidate, err)
				}
				wireView, err := protocol.DecodeUpdateView(vector.UpdateView)
				if err != nil {
					t.Fatal(err)
				}
				base, err := cid.Decode(wireView.BaseRoot)
				if err != nil || maltcid.VersionIDOf(base) != expectedBaseVersion {
					t.Fatalf("base must be a V%d Root: %s (%v)", expectedBaseVersion, wireView.BaseRoot, err)
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
	})
}

func TestClientRootCorpusIsGenerated(t *testing.T) {
	for _, test := range []struct {
		version  string
		generate func() ([]byte, error)
	}{
		{conformance.ClientRootV4, conformancegen.GenerateClientRootV4},
	} {
		t.Run(test.version, func(t *testing.T) {
			want, err := conformance.ClientRootBytesVersion(test.version)
			if err != nil {
				t.Fatal(err)
			}
			got, err := test.generate()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("checked-in client-root vectors.json is stale; run go generate ./conformance")
			}
		})
	}
}

func TestClientRootSchemasAreJSON(t *testing.T) {
	for _, version := range []string{conformance.ClientRootV4} {
		for _, name := range []string{"corpus.schema.json", "vector.schema.json"} {
			data, err := conformance.ClientRootSchemaVersion(version, name)
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(data) {
				t.Fatalf("%s %s is not valid JSON", version, name)
			}
		}
	}
}

func TestClientRootCoverageMatrix(t *testing.T) {
	testClientRootVersions(t, func(t *testing.T, corpus conformance.ClientRootCorpus) {
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
	})
}

func computeClientRootVector(ctx context.Context, vector conformance.ClientRootVector, version string) (
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
	newRuntime := clientwriter.NewRuntime
	if version == conformance.ClientRootV4 {
		newRuntime = clientwriter.NewRuntime
	}
	runtime, err := newRuntime(
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
	result, err := runtime.ComputeBundle(ctx, vector.TransactionID, verified, intent)
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

func testClientRootVersions(t *testing.T, check func(*testing.T, conformance.ClientRootCorpus)) {
	t.Helper()
	for _, version := range []string{conformance.ClientRootV4} {
		t.Run(version, func(t *testing.T) {
			corpus, err := conformance.LoadClientRootVersion(version)
			if err != nil {
				t.Fatal(err)
			}
			check(t, corpus)
		})
	}
}
