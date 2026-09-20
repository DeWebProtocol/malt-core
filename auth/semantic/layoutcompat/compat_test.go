package layoutcompat_test

import (
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func newScheme(t *testing.T, profile maltcid.ProfileID) commitment.IndexCommitment {
	t.Helper()
	var s commitment.IndexCommitment
	var err error
	if profile == maltcid.IPA256 {
		s, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
	} else {
		s, err = kzg.NewScheme()
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCurrentMapAdapterRestartAndUpdates(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			store := memory.New(true)
			m, err := radix.NewMap(newScheme(t, profile), store)
			if err != nil {
				t.Fatal(err)
			}
			first, second := cid.MustParse("bafkqaaa"), cid.MustParse("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku")
			root, err := m.Commit(t.Context(), "map", mapping.NewViewFrom(map[string]cid.Cid{"a": first}))
			if err != nil {
				t.Fatal(err)
			}
			m, err = radix.NewMap(newScheme(t, profile), store)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"a", "missing"} {
				path := arcset.CanonicalizePath(key)
				binding, proof, err := m.Prove(t.Context(), "map", root, path)
				if err != nil {
					t.Fatal(err)
				}
				if valid, err := m.Verify(root, path, binding, proof); err != nil || !valid || binding.Present != (key == "a") {
					t.Fatalf("proof %s: %v", key, err)
				}
			}
			updates := []mapping.BatchUpdate{{Key: arcset.CanonicalizePath("a"), OldValue: first, NewValue: second}, {Key: arcset.CanonicalizePath("b"), NewValue: first}}
			changed, err := m.BatchUpdate(t.Context(), "map", root, updates)
			if err != nil {
				t.Fatal(err)
			}
			want, err := m.Commit(t.Context(), "rebuild", mapping.NewViewFrom(map[string]cid.Cid{"a": second, "b": first}))
			if err != nil || !changed.Equals(want) {
				t.Fatalf("batch differs from rebuild: %v", err)
			}
			if _, err := m.Update(t.Context(), "map", changed, arcset.CanonicalizePath("a"), first, first); err == nil {
				t.Fatal("incorrect old value accepted")
			}
			deleted, err := m.Update(t.Context(), "map", changed, arcset.CanonicalizePath("b"), first, cid.Undef)
			if err != nil {
				t.Fatal(err)
			}
			binding, proof, err := m.Prove(t.Context(), "map", deleted, arcset.CanonicalizePath("b"))
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := m.Verify(deleted, arcset.CanonicalizePath("b"), binding, proof); err != nil || !valid || binding.Present {
				t.Fatalf("deletion proof: %v", err)
			}
		})
	}
}

func TestCurrentListAdapterAcrossNodeBoundary(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			store := memory.New(true)
			scheme := newScheme(t, profile)
			l, err := tree.NewList(scheme, store)
			if err != nil {
				t.Fatal(err)
			}
			values := make([]cid.Cid, scheme.MaxValues())
			for i := range values {
				values[i] = cid.MustParse("bafkqaaa")
			}
			root, err := l.CommitFixed(t.Context(), "list", values, 10, uint64(len(values))*10-3)
			if err != nil {
				t.Fatal(err)
			}
			l, err = tree.NewList(newScheme(t, profile), store)
			if err != nil {
				t.Fatal(err)
			}
			index := uint64(len(values) - 1)
			query, proof, err := l.Prove(t.Context(), "list", root, index)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := l.Verify(root, index, query, proof); err != nil || !valid || !query.Key.Equals(values[index]) || query.Length != uint64(len(values)) {
				t.Fatalf("last element after restart: %v", err)
			}
			start := index*10 - 1
			span, evidence, err := l.ProveRange(t.Context(), "list", root, start, nil)
			if err != nil {
				t.Fatal(err)
			}
			if valid, err := l.VerifyRange(root, start, nil, span, evidence); err != nil || !valid || len(span.Segments) != 2 {
				t.Fatalf("range across node boundary: %v", err)
			}
			plain, err := l.Commit(t.Context(), "plain", list.NewViewFromSlice(values[:len(values)-1]))
			if err != nil {
				t.Fatal(err)
			}
			appended, gotIndex, err := l.Append(t.Context(), "plain", plain, values[0])
			if err != nil || gotIndex != index {
				t.Fatalf("append: %d %v", gotIndex, err)
			}
			want, err := l.Commit(t.Context(), "rebuild", list.NewViewFromSlice(values))
			if err != nil || !appended.Equals(want) {
				t.Fatalf("append differs from rebuild: %v", err)
			}
			truncated, err := l.Truncate(t.Context(), "plain", appended, index)
			if err != nil || !truncated.Equals(plain) {
				t.Fatalf("truncate differs from original: %v", err)
			}
		})
	}
}
