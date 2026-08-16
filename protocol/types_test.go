package protocol_test

import (
	"encoding/json"
	"testing"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	"github.com/dewebprotocol/malt-core/protocol"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestPublishedProtocolSchemasAreJSONObjects(t *testing.T) {
	for _, name := range protocol.SchemaNames() {
		data, err := protocol.Schema(name)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatalf("schema %s: %v", name, err)
		}
		if value["$id"] == nil {
			t.Fatalf("schema %s has no $id", name)
		}
	}
}

func TestMapProofSchemasArePublished(t *testing.T) {
	want := []string{
		"map-proof-request.schema.json",
		"map-proof-result.schema.json",
		"map-proof-verification.schema.json",
	}
	names := protocol.SchemaNames()
	for _, name := range want {
		found := false
		for _, candidate := range names {
			if candidate == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("SchemaNames does not include %s", name)
		}
	}
}

func TestResolveContractRoundTripsCoreValues(t *testing.T) {
	root := protocolTestCID(t, "root")
	target := protocolTestCID(t, "target")
	request := protocol.ResolveRequest{Profile: protocol.ResolveProfile, Root: root.String(), Segments: []string{"a", "@payload"}}
	coreRequest, err := request.Core()
	if err != nil {
		t.Fatal(err)
	}
	if !coreRequest.Root.Equals(root) || len(coreRequest.Segments) != 2 {
		t.Fatalf("core request = %+v", coreRequest)
	}
	result, err := protocol.NewResolveResult(malt.ResolveResult{Target: target, ProofList: prooflist.ProofList{Root: root}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Profile != protocol.ResolveProfile || result.Target != target.String() {
		t.Fatalf("result = %+v", result)
	}
}

func TestReadQueryRejectsMixedFields(t *testing.T) {
	index := uint64(1)
	if err := (protocol.Query{Kind: protocol.QueryMapKey, Segments: []string{"a"}, Index: &index}).Validate(); err == nil {
		t.Fatal("map query accepted list fields")
	}
	query, err := protocol.QueryFromCore(malt.ListIndexQuery(index))
	if err != nil {
		t.Fatal(err)
	}
	if query.Kind != protocol.QueryListIndex || query.Index == nil || *query.Index != index {
		t.Fatalf("query = %+v", query)
	}
}

func protocolTestCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}
