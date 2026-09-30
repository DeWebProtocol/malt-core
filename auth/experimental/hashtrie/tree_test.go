package hashtrie

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func target(text string) cid.Cid {
	hash, _ := mh.Sum([]byte(text), mh.SHA2_256, -1)
	return cid.NewCidV1(cid.Raw, hash)
}
func coord(index int, kind coordinate.Kind) coordinate.Coordinate {
	if kind == coordinate.Index {
		return coordinate.At(uint64(index))
	}
	return coordinate.Coordinate{Kind: coordinate.Key, Key: sha256.Sum256([]byte(fmt.Sprint(index)))}
}
func nodes() Nodes {
	store := memory.New(true)
	return Nodes{Lookup: store, Updater: store, Scope: "experimental-test"}
}
func assertQuery(t *testing.T, root Root, c coordinate.Coordinate, want cid.Cid, store Nodes) Proof {
	t.Helper()
	p, err := Prove(context.Background(), root, c, store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Verify(root, c, p)
	if err != nil {
		t.Fatal(err)
	}
	if result.Present != want.Defined() || result.Present && !result.Target.Equals(want) {
		t.Fatalf("oracle mismatch: %+v", result)
	}
	return p
}

func TestCompactTreeMatchesFullCIDOracleAcrossImmutableUpdates(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []coordinate.Kind{coordinate.Key, coordinate.Index} {
		store := nodes()
		entries := make([]Entry, 256)
		oracle := map[int]cid.Cid{}
		for i := range entries {
			oracle[i] = target(fmt.Sprint("value-", i))
			entries[i] = Entry{coord(i, kind), oracle[i]}
		}
		root, err := Build(ctx, kind, entries, store)
		if err != nil {
			t.Fatal(err)
		}
		initial := root
		shuffled := append([]Entry{}, entries...)
		rand.New(rand.NewSource(9)).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		other, err := Build(ctx, kind, shuffled, nodes())
		if err != nil || other != root {
			t.Fatal("build depends on source iteration order", err)
		}
		for i := 0; i < 320; i++ {
			assertQuery(t, root, coord(i, kind), oracle[i], store)
		}
		for i := 0; i < 64; i++ {
			before := oracle[i]
			after := target(fmt.Sprint("replacement-", i))
			if i%3 == 0 {
				after = cid.Undef
			}
			root, err = Apply(ctx, root, Change{coord(i, kind), before, after}, store)
			if err != nil {
				t.Fatal(err)
			}
			oracle[i] = after
			assertQuery(t, root, coord(i, kind), after, store)
			assertQuery(t, initial, coord(i, kind), before, store)
		}
		for i := 256; i < 280; i++ {
			after := target(fmt.Sprint("new-", i))
			root, err = Apply(ctx, root, Change{coord(i, kind), cid.Undef, after}, store)
			if err != nil {
				t.Fatal(err)
			}
			oracle[i] = after
		}
		for i := 0; i < 320; i++ {
			assertQuery(t, root, coord(i, kind), oracle[i], store)
		}
		rebuilt := []Entry{}
		for i, want := range oracle {
			if want.Defined() {
				rebuilt = append(rebuilt, Entry{coord(i, kind), want})
			}
		}
		fromScratch, err := Build(ctx, kind, rebuilt, nodes())
		if err != nil || fromScratch != root {
			t.Fatal("incremental delta root differs from independent rebuild", err)
		}
		ref, err := root.Reference()
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := maltcid.ParseRoot(ref); err == nil {
			t.Fatal("experimental root accepted as a native MALT Root")
		}
	}
}

func TestProofBindsFullQueryFullTargetAndSelectedRoot(t *testing.T) {
	store := nodes()
	entries := []Entry{{coord(1, coordinate.Key), target("one")}, {coord(2, coordinate.Key), target("two")}, {coord(3, coordinate.Key), target("three")}}
	root, err := Build(context.Background(), coordinate.Key, entries, store)
	if err != nil {
		t.Fatal(err)
	}
	p := assertQuery(t, root, entries[0].Coordinate, entries[0].Target, store)
	if _, err := Verify(root, entries[1].Coordinate, p); err == nil {
		t.Fatal("different full query reused a proof")
	}
	bad := p
	bad.Terminal = append([]byte{}, p.Terminal...)
	bad.Terminal[len(bad.Terminal)-1] ^= 1
	if _, err := Verify(root, entries[0].Coordinate, bad); err == nil {
		t.Fatal("modified complete target accepted")
	}
	bad = p
	bad.Steps = append([]Step{}, p.Steps...)
	bad.Steps[0].Sibling[0] ^= 1
	if _, err := Verify(root, entries[0].Coordinate, bad); err == nil {
		t.Fatal("modified sibling accepted")
	}
	wrongRoot := root
	wrongRoot.Digest[0] ^= 1
	if _, err := Verify(wrongRoot, entries[0].Coordinate, p); err == nil {
		t.Fatal("proof accepted under another selected root")
	}
	if _, err := Apply(context.Background(), root, Change{entries[0].Coordinate, target("wrong-before"), target("after")}, store); err == nil {
		t.Fatal("implicit rebase accepted")
	}
	if _, err := Prove(context.Background(), root, coord(99, coordinate.Key), nodes()); err == nil {
		t.Fatal("missing materialization became authenticated absence")
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip Proof
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, entries[0].Coordinate, roundTrip); err != nil {
		t.Fatal(err)
	}
}

func TestEmptySingletonDeletionAndCompactProofBudget(t *testing.T) {
	ctx := context.Background()
	store := nodes()
	root, err := Build(ctx, coordinate.Index, nil, store)
	if err != nil {
		t.Fatal(err)
	}
	assertQuery(t, root, coordinate.At(0), cid.Undef, store)
	root, err = Apply(ctx, root, Change{coordinate.At(0), cid.Undef, target("one")}, store)
	if err != nil {
		t.Fatal(err)
	}
	assertQuery(t, root, coordinate.At(1), cid.Undef, store)
	root, err = Apply(ctx, root, Change{coordinate.At(0), target("one"), cid.Undef}, store)
	if err != nil {
		t.Fatal(err)
	}
	assertQuery(t, root, coordinate.At(0), cid.Undef, store)
	entries := make([]Entry, 4096)
	for i := range entries {
		entries[i] = Entry{coord(i, coordinate.Key), target(fmt.Sprint(i))}
	}
	root, err = Build(ctx, coordinate.Key, entries, store)
	if err != nil {
		t.Fatal(err)
	}
	p := assertQuery(t, root, coord(100, coordinate.Key), entries[100].Target, store)
	if len(p.Steps) > 32 || len(p.Terminal) > 128 {
		t.Fatalf("compact hash baseline emitted a wide or linear witness: steps=%d terminal=%d", len(p.Steps), len(p.Terminal))
	}
}

func TestDivergentBranchCannotLeaveAncestorPath(t *testing.T) {
	query := coordinate.At(7)
	k, _ := query.Encode()
	path := route(coordinate.Index, k)
	// Commit a malformed branch on the opposite side of its declared ancestor.
	p := prefix(path, 1)
	p[0] ^= 0x80
	terminal, err := branchBody(coordinate.Index, 1, p, hashNode([]byte("left")), hashNode([]byte("right")))
	if err != nil {
		t.Fatal(err)
	}
	step := Step{Split: 0, Prefix: Digest{}, Sibling: hashNode([]byte("sibling"))}
	left, right := hashNode(terminal), step.Sibling
	if bit(path, 0) == 1 {
		left, right = right, left
	}
	body, err := branchBody(coordinate.Index, 0, step.Prefix, left, right)
	if err != nil {
		t.Fatal(err)
	}
	proof := Proof{Schema: ProofSchema, Key: k, Steps: []Step{step}, Terminal: terminal}
	if _, err := Verify(newRoot(coordinate.Index, hashNode(body)), query, proof); err == nil {
		t.Fatal("malformed compressed branch authenticated absence")
	}
}
