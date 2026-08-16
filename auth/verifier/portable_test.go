package verifier_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	listtree "github.com/dewebprotocol/malt-core/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	mapradix "github.com/dewebprotocol/malt-core/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	authverifier "github.com/dewebprotocol/malt-core/auth/verifier"
	"github.com/dewebprotocol/malt-core/execution"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestPortableVerifierAcceptsRuntimeRadixAndTreeProofs(t *testing.T) {
	factories := map[string]func(*testing.T) commitment.IndexCommitment{
		"ipa": func(t *testing.T) commitment.IndexCommitment {
			t.Helper()
			scheme, err := ipa.NewScheme()
			if err != nil {
				t.Fatalf("ipa.NewScheme: %v", err)
			}
			return scheme
		},
		"kzg": func(t *testing.T) commitment.IndexCommitment {
			t.Helper()
			scheme, err := kzg.NewScheme()
			if err != nil {
				t.Fatalf("kzg.NewScheme: %v", err)
			}
			return scheme
		},
	}

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			table := materialmemory.New(true)
			scheme := factory(t)
			maps, err := mapradix.NewMap(scheme, table)
			if err != nil {
				t.Fatalf("radix.NewMap: %v", err)
			}
			lists, err := listtree.NewList(scheme, table)
			if err != nil {
				t.Fatalf("tree.NewList: %v", err)
			}
			portable, err := authverifier.NewDefault()
			if err != nil {
				t.Fatalf("NewDefault: %v", err)
			}

			t.Run("map", func(t *testing.T) {
				target := portableTestCID(t, "profile-name")
				root, err := maps.Commit(ctx, "portable-map-"+name, mapping.NewViewFrom(map[string]cid.Cid{"profile/name": target}))
				if err != nil {
					t.Fatalf("Commit: %v", err)
				}
				binding, proof, err := maps.Prove(ctx, "portable-map-"+name, root, arcset.CanonicalizePath("profile/name"))
				if err != nil {
					t.Fatalf("Prove: %v", err)
				}
				pl := prooflist.ProofList{Root: root, Query: "profile/name", Steps: []prooflist.Step{{
					Kind: prooflist.KindMapStep, From: root, Path: "profile/name", Target: binding.Value,
					EvidenceKind: "structure", EvidenceBackend: "map", Proof: proof,
				}}}
				assertPortableValid(t, portable, pl)

				if name == "kzg" {
					malformedRoot := portableMalformedRoot(t, root)
					malformed := pl
					malformed.Root = malformedRoot
					malformed.Steps = append([]prooflist.Step(nil), pl.Steps...)
					malformed.Steps[0].From = malformedRoot
					assertPortableRejected(t, portable, malformed)
				}

				pl.Steps[0].Target = portableTestCID(t, "forged-map-target")
				assertPortableRejected(t, portable, pl)
			})

			t.Run("map_absence", func(t *testing.T) {
				tests := []struct {
					name    string
					present map[arcset.Path]cid.Cid
					absent  arcset.Path
				}{
					{name: "empty", present: map[arcset.Path]cid.Cid{}, absent: arcset.CanonicalizePath("definitely-absent")},
				}
				presentKey := arcset.CanonicalizePath("present-leaf")
				tests = append(tests, struct {
					name    string
					present map[arcset.Path]cid.Cid
					absent  arcset.Path
				}{
					name:    "conflicting_leaf",
					present: map[arcset.Path]cid.Cid{presentKey: portableTestCID(t, "absence-present-"+name)},
					absent:  portableSharedFirstDigitPath(t, scheme.MaxValues(), presentKey),
				})
				for _, test := range tests {
					t.Run(test.name, func(t *testing.T) {
						scope := fmt.Sprintf("portable-map-absence-%s-%s", name, test.name)
						root, err := maps.Commit(ctx, scope, mapping.NewViewFromPaths(test.present))
						if err != nil {
							t.Fatalf("Commit: %v", err)
						}
						executor, err := execution.NewExecutor(execution.Options{Scope: scope, Maps: maps})
						if err != nil {
							t.Fatalf("NewExecutor: %v", err)
						}
						request := malt.MapProofRequest{Root: root, Key: test.absent}
						result, err := executor.ProveMap(ctx, request)
						if err != nil {
							t.Fatalf("ProveMap: %v", err)
						}
						if result.Present || result.Target.Defined() || result.ProofList.Steps[0].Kind != prooflist.KindMapAbsence {
							t.Fatalf("absence result = %+v", result)
						}
						if err := malt.VerifyMapProof(ctx, request, result, portable); err != nil {
							t.Fatalf("VerifyMapProof: %v", err)
						}
						wrong := request
						wrong.Key = arcset.CanonicalizePath("another-missing-key")
						if err := malt.VerifyMapProof(ctx, wrong, result, portable); err == nil {
							t.Fatal("VerifyMapProof accepted absence for another key")
						}
					})
				}
			})

			t.Run("generic_map_coordinates", func(t *testing.T) {
				tests := []struct {
					name       string
					coordinate string
				}{
					{name: "current_directory", coordinate: "."},
					{name: "parent_directory", coordinate: ".."},
					{name: "surrounding_whitespace", coordinate: " profile "},
					{name: "nul", coordinate: "profile\x00name"},
				}
				for _, test := range tests {
					t.Run(test.name, func(t *testing.T) {
						target := portableTestCID(t, "generic-"+test.name)
						scope := fmt.Sprintf("portable-generic-map-%s-%s", name, test.name)
						root, err := maps.Commit(ctx, scope, mapping.NewViewFrom(map[string]cid.Cid{test.coordinate: target}))
						if err != nil {
							t.Fatalf("Commit: %v", err)
						}
						executor, err := execution.NewExecutor(execution.Options{Scope: scope, Maps: maps})
						if err != nil {
							t.Fatalf("NewExecutor: %v", err)
						}
						query, err := malt.MapKeyQuery(test.coordinate)
						if err != nil {
							t.Fatalf("MapKeyQuery: %v", err)
						}
						request := malt.ReadRequest{Root: root, Query: query}
						result, err := executor.Read(ctx, request)
						if err != nil {
							t.Fatalf("Read: %v", err)
						}
						if !result.Target.Equals(target) {
							t.Fatalf("target = %s, want %s", result.Target, target)
						}
						if err := malt.VerifyRead(ctx, request, result, portable); err != nil {
							t.Fatalf("VerifyRead: %v", err)
						}
					})
				}
			})

			if name == "kzg" {
				t.Run("map_twelve_bit_second_level", func(t *testing.T) {
					first, second := portableSharedFirstKZGDigitPaths(t)
					firstTarget := portableTestCID(t, "twelve-bit-first")
					secondTarget := portableTestCID(t, "twelve-bit-second")
					scope := "portable-map-kzg-twelve-bit"
					root, err := maps.Commit(ctx, scope, mapping.NewViewFrom(map[string]cid.Cid{
						first:  firstTarget,
						second: secondTarget,
					}))
					if err != nil {
						t.Fatalf("Commit: %v", err)
					}
					binding, proof, err := maps.Prove(ctx, scope, root, arcset.CanonicalizePath(first))
					if err != nil {
						t.Fatalf("Prove: %v", err)
					}
					pl := prooflist.ProofList{Root: root, Query: first, Steps: []prooflist.Step{{
						Kind: prooflist.KindMapStep, From: root, Path: first, Target: binding.Value,
						EvidenceKind: "structure", EvidenceBackend: "map", Proof: proof,
					}}}
					assertPortableValid(t, portable, pl)

					pl.Query = second
					pl.Steps[0].Path = second
					assertPortableRejected(t, portable, pl)
				})
			}

			t.Run("list_index", func(t *testing.T) {
				values := []cid.Cid{portableTestCID(t, "list-0"), portableTestCID(t, "list-1")}
				root, err := lists.Commit(ctx, "portable-list-"+name, list.NewViewFromSlice(values))
				if err != nil {
					t.Fatalf("Commit: %v", err)
				}
				index := uint64(1)
				query, proof, err := lists.Prove(ctx, "portable-list-"+name, root, index)
				if err != nil {
					t.Fatalf("Prove: %v", err)
				}
				length := query.Length
				pl := prooflist.ProofList{Root: root, Query: "list:1", Steps: []prooflist.Step{{
					Kind: prooflist.KindListIndex, From: root, Index: &index, Length: &length, Target: query.Key,
					EvidenceKind: "structure", EvidenceBackend: "list", Proof: proof,
				}}}
				assertPortableValid(t, portable, pl)

				pl.Query = "list:0"
				assertPortableRejected(t, portable, pl)
			})

			t.Run("list_range", func(t *testing.T) {
				chunks := []cid.Cid{portableTestCID(t, "chunk-0"), portableTestCID(t, "chunk-1")}
				root, err := lists.CommitFixed(ctx, "portable-range-"+name, chunks, 8, 12)
				if err != nil {
					t.Fatalf("CommitFixed: %v", err)
				}
				start, end := uint64(2), uint64(10)
				result, proof, err := lists.ProveRange(ctx, "portable-range-"+name, root, start, &end)
				if err != nil {
					t.Fatalf("ProveRange: %v", err)
				}
				childCount := result.Metadata.ChildCount
				totalSize := result.Metadata.TotalSize
				chunkSize := result.Metadata.ChunkSize
				pl := prooflist.ProofList{Root: root, Query: "range:2:10", Steps: []prooflist.Step{{
					Kind: prooflist.KindListRange, From: root, Target: root, Start: &start, End: &end,
					ChildCount: &childCount, TotalSize: &totalSize, ChunkSize: &chunkSize, Segments: result.Segments,
					EvidenceKind: "structure", EvidenceBackend: "measured_list", Proof: proof,
				}}}
				assertPortableValid(t, portable, pl)

				pl.Query = "range:3:10"
				assertPortableRejected(t, portable, pl)
			})
		})
	}
}

func assertPortableValid(t *testing.T, verifier *authverifier.Verifier, pl prooflist.ProofList) {
	t.Helper()
	ok, err := verifier.VerifyProofList(context.Background(), pl)
	if err != nil {
		t.Fatalf("VerifyProofList: %v", err)
	}
	if !ok {
		t.Fatal("VerifyProofList returned false")
	}
}

func assertPortableRejected(t *testing.T, verifier *authverifier.Verifier, pl prooflist.ProofList) {
	t.Helper()
	ok, err := verifier.VerifyProofList(context.Background(), pl)
	if err == nil && ok {
		t.Fatal("VerifyProofList accepted tampered artifact")
	}
}

func portableTestCID(t *testing.T, seed string) cid.Cid {
	t.Helper()
	sum, err := mh.Sum([]byte(fmt.Sprintf("portable:%s", seed)), mh.SHA2_256, -1)
	if err != nil {
		t.Fatalf("hash seed: %v", err)
	}
	return cid.NewCidV1(cid.Raw, sum)
}

func portableMalformedRoot(t *testing.T, root cid.Cid) cid.Cid {
	t.Helper()
	digest, err := maltcid.ExtractCommitment(root)
	if err != nil {
		t.Fatalf("ExtractCommitment: %v", err)
	}
	digest = append(append([]byte(nil), digest...), 0x42)
	hash, err := mh.Encode(digest, mh.IDENTITY)
	if err != nil {
		t.Fatalf("encode malformed root: %v", err)
	}
	return cid.NewCidV1(root.Prefix().Codec, hash)
}

func portableSharedFirstKZGDigitPaths(t *testing.T) (string, string) {
	t.Helper()
	type digits struct {
		first  uint16
		second uint16
	}
	pathDigits := func(path string) digits {
		digest := sha256.Sum256([]byte(arcset.CanonicalizePath(path).String()))
		return digits{
			first:  uint16(digest[0])<<4 | uint16(digest[1]>>4),
			second: uint16(digest[1]&0x0f)<<8 | uint16(digest[2]),
		}
	}
	seen := make(map[uint16]struct {
		path   string
		second uint16
	})
	for i := 0; i < 1<<16; i++ {
		path := fmt.Sprintf("portable-shared-prefix-%d", i)
		digits := pathDigits(path)
		if previous, ok := seen[digits.first]; ok && previous.second != digits.second {
			return previous.path, path
		}
		seen[digits.first] = struct {
			path   string
			second uint16
		}{path: path, second: digits.second}
	}
	t.Fatal("could not find portable KZG paths with a shared first digit")
	return "", ""
}

func portableSharedFirstDigitPath(t *testing.T, capacity int, base arcset.Path) arcset.Path {
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
		candidate := arcset.CanonicalizePath(fmt.Sprintf("portable-absent-shared-%d", index))
		digest := sha256.Sum256([]byte(candidate.String()))
		if digit, ok := geometry.MapDigit(digest[:], 0); ok && digit == baseDigit && candidate != base {
			return candidate
		}
	}
	t.Fatal("could not find portable absent path with a shared first digit")
	return ""
}
