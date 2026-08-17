package radix_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type schemeFactory func(t *testing.T) commitment.IndexCommitment

const testNamespace = "map-radix-semantic-test"

func mappingSchemes() map[string]schemeFactory {
	return map[string]schemeFactory{
		"ipa": func(t *testing.T) commitment.IndexCommitment {
			t.Helper()
			scheme, err := ipa.NewScheme()
			if err != nil {
				t.Fatalf("ipa.NewScheme failed: %v", err)
			}
			return scheme
		},
		"kzg": func(t *testing.T) commitment.IndexCommitment {
			t.Helper()
			scheme, err := kzg.NewScheme()
			if err != nil {
				t.Fatalf("kzg.NewScheme failed: %v", err)
			}
			return scheme
		},
	}
}

func newMap(t *testing.T, factory schemeFactory, store *materialmemory.Store) mapping.Semantics {
	t.Helper()
	if store == nil {
		store = materialmemory.New(true)
	}
	semantic, err := mappingradix.NewMap(factory(t), store)
	if err != nil {
		t.Fatalf("radix.NewMap failed: %v", err)
	}
	return semantic
}

func fakeCID(seed string) cid.Cid {
	sum, err := mh.Sum([]byte(seed), mh.SHA2_256, -1)
	if err != nil {
		panic(err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

func firstKZGDigit(path string) uint16 {
	digest := sha256.Sum256([]byte(arcset.CanonicalizePath(path).String()))
	return uint16(digest[0])<<4 | uint16(digest[1]>>4)
}

func secondKZGDigit(path string) uint16 {
	digest := sha256.Sum256([]byte(arcset.CanonicalizePath(path).String()))
	return uint16(digest[1]&0x0f)<<8 | uint16(digest[2])
}

func findPathsWithAliasedLowByte(t *testing.T) (string, string) {
	t.Helper()
	seen := make(map[byte]struct {
		path  string
		digit uint16
	})
	for i := 0; i < 1<<16; i++ {
		path := fmt.Sprintf("high-slot-%d", i)
		digit := firstKZGDigit(path)
		if digit <= 255 {
			continue
		}
		key := byte(digit)
		if previous, ok := seen[key]; ok && previous.digit != digit {
			return previous.path, path
		}
		seen[key] = struct {
			path  string
			digit uint16
		}{path: path, digit: digit}
	}
	t.Fatal("could not find high-slot paths with aliased low bytes")
	return "", ""
}

func findPathsWithSharedFirstKZGDigit(t *testing.T) (string, string) {
	t.Helper()
	seen := make(map[uint16]string)
	for i := 0; i < 1<<16; i++ {
		path := fmt.Sprintf("shared-prefix-%d", i)
		first := firstKZGDigit(path)
		if previous, ok := seen[first]; ok && secondKZGDigit(previous) != secondKZGDigit(path) {
			return previous, path
		}
		seen[first] = path
	}
	t.Fatal("could not find paths with a shared first KZG digit")
	return "", ""
}

func findPathWithSharedFirstDigit(t *testing.T, capacity int, base arcset.Path) arcset.Path {
	t.Helper()
	geometry, err := nodegeometry.ForCapacity(capacity)
	if err != nil {
		t.Fatal(err)
	}
	baseDigest := sha256.Sum256([]byte(base.String()))
	baseDigit, ok := geometry.MapDigit(baseDigest[:], 0)
	if !ok {
		t.Fatal("base path has no first radix digit")
	}
	for index := 0; index < 1<<18; index++ {
		candidate := arcset.CanonicalizePath(fmt.Sprintf("absent-shared-%d", index))
		digest := sha256.Sum256([]byte(candidate.String()))
		if digit, ok := geometry.MapDigit(digest[:], 0); ok && digit == baseDigit && candidate != base {
			return candidate
		}
	}
	t.Fatal("could not find absent path with shared first digit")
	return ""
}

func TestMapCommitProveVerify(t *testing.T) {
	ctx := context.Background()
	view := mapping.NewViewFrom(map[string]cid.Cid{
		"b/c":      fakeCID("value-bc"),
		"a":        fakeCID("value-a"),
		"@payload": fakeCID("value-payload"),
	})

	for name, factory := range mappingSchemes() {
		t.Run(name, func(t *testing.T) {
			semantic := newMap(t, factory, nil)

			root, err := semantic.Commit(ctx, testNamespace, view)
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}

			key := arcset.CanonicalizePath("b/c")
			binding, proof, err := semantic.Prove(ctx, testNamespace, root, key)
			if err != nil {
				t.Fatalf("Prove failed: %v", err)
			}
			if !binding.Present {
				t.Fatal("expected membership binding")
			}
			if !binding.Value.Equals(fakeCID("value-bc")) {
				t.Fatalf("binding value mismatch: %s", binding.Value)
			}

			ok, err := semantic.Verify(root, key, binding, proof)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
			if !ok {
				t.Fatal("expected proof to verify")
			}

			ok, err = semantic.Verify(root, arcset.CanonicalizePath("a"), binding, proof)
			if err == nil && ok {
				t.Fatal("expected proof to be path-bound")
			}
		})
	}
}

func TestMapProvesEmptySlotAndConflictingLeafAbsence(t *testing.T) {
	ctx := context.Background()
	for name, factory := range mappingSchemes() {
		t.Run(name, func(t *testing.T) {
			scheme := factory(t)
			semantic, err := mappingradix.NewMap(scheme, materialmemory.New(true))
			if err != nil {
				t.Fatal(err)
			}

			emptyRoot, err := semantic.Commit(ctx, testNamespace+"-absence-empty-"+name, mapping.NewViewFrom(nil))
			if err != nil {
				t.Fatalf("Commit(empty) failed: %v", err)
			}
			emptyKey := arcset.CanonicalizePath("definitely-absent")
			emptyBinding, emptyProof, err := semantic.Prove(ctx, testNamespace+"-absence-empty-"+name, emptyRoot, emptyKey)
			if err != nil {
				t.Fatalf("Prove(empty absence) failed: %v", err)
			}
			if emptyBinding.Present || emptyBinding.Value.Defined() {
				t.Fatalf("empty absence binding = %+v", emptyBinding)
			}
			if ok, err := semantic.Verify(emptyRoot, emptyKey, emptyBinding, emptyProof); err != nil || !ok {
				t.Fatalf("Verify(empty absence) = %v, %v", ok, err)
			}

			presentKey := arcset.CanonicalizePath("present-leaf")
			presentValue := fakeCID("present-leaf-value-" + name)
			namespace := testNamespace + "-absence-leaf-" + name
			root, err := semantic.Commit(ctx, namespace, mapping.NewViewFromPaths(map[arcset.Path]cid.Cid{presentKey: presentValue}))
			if err != nil {
				t.Fatalf("Commit(single leaf) failed: %v", err)
			}
			absentKey := findPathWithSharedFirstDigit(t, scheme.MaxValues(), presentKey)
			binding, proof, err := semantic.Prove(ctx, namespace, root, absentKey)
			if err != nil {
				t.Fatalf("Prove(conflicting leaf absence) failed: %v", err)
			}
			if binding.Present || binding.Value.Defined() {
				t.Fatalf("conflicting leaf absence binding = %+v", binding)
			}
			if ok, err := semantic.Verify(root, absentKey, binding, proof); err != nil || !ok {
				t.Fatalf("Verify(conflicting leaf absence) = %v, %v", ok, err)
			}
			if ok, err := semantic.Verify(root, presentKey, binding, proof); err == nil && ok {
				t.Fatal("absence proof verified for the present path")
			}
		})
	}
}

func TestKZGMapUsesFullTwelveBitSlots(t *testing.T) {
	ctx := context.Background()
	namespace := "map-radix-kzg-high-slots"
	store := materialmemory.New(true)
	semantic := newMap(t, mappingSchemes()["kzg"], store)

	first, second := findPathsWithAliasedLowByte(t)
	firstDigit := firstKZGDigit(first)
	secondDigit := firstKZGDigit(second)
	if firstDigit <= 255 || secondDigit <= 255 {
		t.Fatalf("test paths do not use high slots: %d, %d", firstDigit, secondDigit)
	}
	if firstDigit == secondDigit || byte(firstDigit) != byte(secondDigit) {
		t.Fatalf("test paths do not exercise byte aliasing: %d, %d", firstDigit, secondDigit)
	}

	values := map[string]cid.Cid{
		first:  fakeCID("high-slot-first"),
		second: fakeCID("high-slot-second"),
	}
	root, err := semantic.Commit(ctx, namespace, mapping.NewViewFrom(values))
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	for path, want := range values {
		digit := firstKZGDigit(path)
		materializedPath := arcset.CanonicalizePath(fmt.Sprintf(
			"runtime/map/radix/nodes/%s/slots/%d", root.String(), digit,
		))
		if _, err := store.Get(ctx, namespace, cid.Undef, materializedPath); err != nil {
			t.Fatalf("slot %d was not materialized at its full-width path: %v", digit, err)
		}
		binding, proof, err := semantic.Prove(ctx, namespace, root, arcset.CanonicalizePath(path))
		if err != nil {
			t.Fatalf("Prove(%q) failed: %v", path, err)
		}
		if !binding.Value.Equals(want) {
			t.Fatalf("Prove(%q) value = %s, want %s", path, binding.Value, want)
		}
		ok, err := semantic.Verify(root, arcset.CanonicalizePath(path), binding, proof)
		if err != nil || !ok {
			t.Fatalf("Verify(%q) = %v, %v", path, ok, err)
		}
	}

	replacement := fakeCID("high-slot-first-replaced")
	updatedRoot, err := semantic.Update(
		ctx,
		namespace,
		root,
		arcset.CanonicalizePath(first),
		values[first],
		replacement,
	)
	if err != nil {
		t.Fatalf("Update high-slot key failed: %v", err)
	}
	values[first] = replacement
	expectedRoot, err := semantic.Commit(ctx, namespace, mapping.NewViewFrom(values))
	if err != nil {
		t.Fatalf("Commit updated view failed: %v", err)
	}
	if !updatedRoot.Equals(expectedRoot) {
		t.Fatalf("updated root = %s, want fresh root %s", updatedRoot, expectedRoot)
	}
}

func TestKZGMapConsumesSecondTwelveBitDigit(t *testing.T) {
	ctx := context.Background()
	namespace := "map-radix-kzg-two-level"
	semantic := newMap(t, mappingSchemes()["kzg"], nil)
	first, second := findPathsWithSharedFirstKZGDigit(t)

	values := map[string]cid.Cid{
		first:  fakeCID("shared-prefix-first"),
		second: fakeCID("shared-prefix-second"),
	}
	root, err := semantic.Commit(ctx, namespace, mapping.NewViewFrom(values))
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	for path, want := range values {
		binding, proof, err := semantic.Prove(ctx, namespace, root, arcset.CanonicalizePath(path))
		if err != nil {
			t.Fatalf("Prove(%q) failed: %v", path, err)
		}
		var envelope struct {
			Steps []json.RawMessage `json:"steps"`
		}
		if err := json.Unmarshal(proof, &envelope); err != nil {
			t.Fatalf("decode proof: %v", err)
		}
		if len(envelope.Steps) != 2 {
			t.Fatalf("proof for %q has %d steps, want 2", path, len(envelope.Steps))
		}
		if !binding.Value.Equals(want) {
			t.Fatalf("Prove(%q) value = %s, want %s", path, binding.Value, want)
		}
		ok, err := semantic.Verify(root, arcset.CanonicalizePath(path), binding, proof)
		if err != nil || !ok {
			t.Fatalf("Verify(%q) = %v, %v", path, ok, err)
		}
	}

	binding, proof, err := semantic.Prove(ctx, namespace, root, arcset.CanonicalizePath(first))
	if err != nil {
		t.Fatalf("Prove for depth-bound test failed: %v", err)
	}
	var oversized struct {
		Steps  []json.RawMessage `json:"steps"`
		Bucket json.RawMessage   `json:"bucket,omitempty"`
	}
	if err := json.Unmarshal(proof, &oversized); err != nil {
		t.Fatalf("decode proof for depth-bound test: %v", err)
	}
	for len(oversized.Steps) < 23 {
		oversized.Steps = append(oversized.Steps, oversized.Steps[0])
	}
	oversizedProof, err := json.Marshal(oversized)
	if err != nil {
		t.Fatalf("encode oversized proof: %v", err)
	}
	if ok, err := semantic.Verify(root, arcset.CanonicalizePath(first), binding, oversizedProof); err == nil || ok {
		t.Fatalf("Verify accepted 23-step KZG radix proof: ok=%v err=%v", ok, err)
	}

	replacement := fakeCID("shared-prefix-first-replaced")
	updatedRoot, err := semantic.Update(
		ctx,
		namespace,
		root,
		arcset.CanonicalizePath(first),
		values[first],
		replacement,
	)
	if err != nil {
		t.Fatalf("Update shared-prefix key failed: %v", err)
	}
	values[first] = replacement
	expectedRoot, err := semantic.Commit(ctx, namespace, mapping.NewViewFrom(values))
	if err != nil {
		t.Fatalf("Commit updated shared-prefix view failed: %v", err)
	}
	if !updatedRoot.Equals(expectedRoot) {
		t.Fatalf("updated shared-prefix root = %s, want fresh root %s", updatedRoot, expectedRoot)
	}
}

func TestMapUpdateReplaceInsertDelete(t *testing.T) {
	ctx := context.Background()
	initialEntries := map[string]cid.Cid{
		"a": fakeCID("value-a"),
		"c": fakeCID("value-c"),
	}

	for name, factory := range mappingSchemes() {
		t.Run(name, func(t *testing.T) {
			semantic := newMap(t, factory, nil)
			initialView := mapping.NewViewFrom(initialEntries)

			root, err := semantic.Commit(ctx, testNamespace, initialView)
			if err != nil {
				t.Fatalf("Commit(initial) failed: %v", err)
			}

			replacement := fakeCID("value-c2")
			replacedRoot, err := semantic.Update(
				ctx,
				testNamespace,
				root,
				arcset.CanonicalizePath("c"),
				initialEntries["c"],
				replacement,
			)
			if err != nil {
				t.Fatalf("Update(replace) failed: %v", err)
			}

			replacedView := mapping.NewViewFrom(map[string]cid.Cid{
				"a": initialEntries["a"],
				"c": replacement,
			})
			expectedReplacedRoot, err := semantic.Commit(ctx, testNamespace, replacedView)
			if err != nil {
				t.Fatalf("Commit(replaced) failed: %v", err)
			}
			if !replacedRoot.Equals(expectedReplacedRoot) {
				t.Fatalf("replace root mismatch: got %s want %s", replacedRoot, expectedReplacedRoot)
			}

			inserted := fakeCID("value-b")
			insertedRoot, err := semantic.Update(
				ctx,
				testNamespace,
				replacedRoot,
				arcset.CanonicalizePath("b"),
				cid.Undef,
				inserted,
			)
			if err != nil {
				t.Fatalf("Update(insert) failed: %v", err)
			}

			insertedView := mapping.NewViewFrom(map[string]cid.Cid{
				"a": initialEntries["a"],
				"b": inserted,
				"c": replacement,
			})
			expectedInsertedRoot, err := semantic.Commit(ctx, testNamespace, insertedView)
			if err != nil {
				t.Fatalf("Commit(inserted) failed: %v", err)
			}
			if !insertedRoot.Equals(expectedInsertedRoot) {
				t.Fatalf("insert root mismatch: got %s want %s", insertedRoot, expectedInsertedRoot)
			}

			deletedRoot, err := semantic.Update(
				ctx,
				testNamespace,
				insertedRoot,
				arcset.CanonicalizePath("a"),
				initialEntries["a"],
				cid.Undef,
			)
			if err != nil {
				t.Fatalf("Update(delete) failed: %v", err)
			}

			deletedView := mapping.NewViewFrom(map[string]cid.Cid{
				"b": inserted,
				"c": replacement,
			})
			expectedDeletedRoot, err := semantic.Commit(ctx, testNamespace, deletedView)
			if err != nil {
				t.Fatalf("Commit(deleted) failed: %v", err)
			}
			if !deletedRoot.Equals(expectedDeletedRoot) {
				t.Fatalf("delete root mismatch: got %s want %s", deletedRoot, expectedDeletedRoot)
			}
		})
	}
}

func TestMapUpdateRejectsInconsistentOldValue(t *testing.T) {
	ctx := context.Background()
	view := mapping.NewViewFrom(map[string]cid.Cid{
		"a": fakeCID("value-a"),
	})

	for name, factory := range mappingSchemes() {
		t.Run(name, func(t *testing.T) {
			semantic := newMap(t, factory, nil)
			root, err := semantic.Commit(ctx, testNamespace, view)
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}

			_, err = semantic.Update(
				ctx,
				testNamespace,
				root,
				arcset.CanonicalizePath("a"),
				fakeCID("wrong-old"),
				fakeCID("value-a2"),
			)
			if err == nil {
				t.Fatal("expected old-value mismatch error")
			}
		})
	}
}

func TestMapRestartSafeProveAndUpdate(t *testing.T) {
	ctx := context.Background()
	initial := mapping.NewViewFrom(map[string]cid.Cid{
		"a":       fakeCID("value-a"),
		"aa":      fakeCID("value-aa"),
		"aa/beta": fakeCID("value-aa-beta"),
	})

	for name, factory := range mappingSchemes() {
		t.Run(name, func(t *testing.T) {
			store := materialmemory.New(true)
			semantic := newMap(t, factory, store)

			root, err := semantic.Commit(ctx, testNamespace, initial)
			if err != nil {
				t.Fatalf("Commit failed: %v", err)
			}

			restarted := newMap(t, factory, store)
			key := arcset.CanonicalizePath("aa/beta")
			binding, proof, err := restarted.Prove(ctx, testNamespace, root, key)
			if err != nil {
				t.Fatalf("Prove after restart failed: %v", err)
			}
			if !binding.Present || !binding.Value.Equals(fakeCID("value-aa-beta")) {
				t.Fatalf("unexpected binding after restart: %+v", binding)
			}

			ok, err := restarted.Verify(root, key, binding, proof)
			if err != nil {
				t.Fatalf("Verify after restart failed: %v", err)
			}
			if !ok {
				t.Fatal("expected restarted proof to verify")
			}

			updatedRoot, err := restarted.Update(
				ctx,
				testNamespace,
				root,
				arcset.CanonicalizePath("a"),
				fakeCID("value-a"),
				fakeCID("value-a2"),
			)
			if err != nil {
				t.Fatalf("Update after restart failed: %v", err)
			}

			expectedRoot, err := restarted.Commit(ctx, testNamespace, mapping.NewViewFrom(map[string]cid.Cid{
				"a":       fakeCID("value-a2"),
				"aa":      fakeCID("value-aa"),
				"aa/beta": fakeCID("value-aa-beta"),
			}))
			if err != nil {
				t.Fatalf("Commit(expected) failed: %v", err)
			}
			if !updatedRoot.Equals(expectedRoot) {
				t.Fatalf("restart-safe update root mismatch: got %s want %s", updatedRoot, expectedRoot)
			}
		})
	}
}
