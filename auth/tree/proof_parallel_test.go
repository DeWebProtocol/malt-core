package tree_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

type gatedProfile struct {
	commitment.Backend
	profile maltcid.ProfileID
	entered chan string
	release chan struct{}
	active  atomic.Int32
	peak    atomic.Int32
}

func (p *gatedProfile) ProfileID() maltcid.ProfileID { return p.profile }
func (p *gatedProfile) PrepareOpening(root commitment.Value, cells []commitment.Cell) (commitment.Opening, error) {
	o, err := p.Backend.(commitment.PreparedProver).PrepareOpening(root, cells)
	if err != nil {
		return nil, err
	}
	return &gatedOpening{Opening: o, profile: p}, nil
}

type gatedOpening struct {
	commitment.Opening
	profile *gatedProfile
}

func (o *gatedOpening) Open(index uint64) (commitment.Cell, []byte, error) {
	p := o.profile
	n := p.active.Add(1)
	defer p.active.Add(-1)
	for old := p.peak.Load(); n > old && !p.peak.CompareAndSwap(old, n); old = p.peak.Load() {
	}
	p.entered <- o.Root().String()
	<-p.release
	return o.Opening.Open(index)
}

type corruptChild struct {
	materializer.NodeLookup
	root maltcid.NodeRef
}

func (s corruptChild) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	cells, err := s.NodeLookup.GetNode(ctx, ref)
	if err == nil && string(ref.Commitment) != string(s.root.Commitment) {
		cells = commitment.CloneCells(cells)
		// Preserve the selected route while corrupting another committed slot.
		cells[len(cells)-1] = commitment.NewCell([]byte("inconsistent witness"))
	}
	return cells, err
}

func TestDistinctVectorsOpenConcurrentlyWithoutChangingEvidence(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, profile := range []maltcid.ProfileID{maltcid.IPA256, maltcid.KZG4096} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			var backend commitment.Backend
			var err error
			if profile == maltcid.IPA256 {
				backend, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
			} else {
				backend, err = kzg.NewScheme()
			}
			if err != nil {
				t.Fatal(err)
			}
			registry := tree.NewRegistry()
			if err = registry.Register(backend.(tree.Profile)); err != nil {
				t.Fatal(err)
			}
			derive := func(_ uint8, label []byte) (coordinate.Coordinate, error) { return coordinate.Parse(label) }
			e := tree.New(registry, derive)
			var first, second [32]byte
			first[8], second[8] = 1, 2
			view := tree.View{Descriptor: maltcid.RootDescriptor{Profile: profile, Layout: maltcid.Map, DerivationProfile: 240}}
			for _, key := range [][32]byte{first, second} {
				view.Bindings = append(view.Bindings, tree.CoordinateBinding{Coordinate: coordinate.Coordinate{Kind: coordinate.Key, Key: key}, Label: coordinate.EncodeKey(key), Target: cid.MustParse("bafkqaaa")})
			}
			nodes := memory.NewNodes()
			root, err := e.Commit(t.Context(), view, nodes)
			if err != nil {
				t.Fatal(err)
			}
			query := tree.Selector{Coordinate: view.Bindings[0].Coordinate, Label: view.Bindings[0].Label}
			runtime.GOMAXPROCS(1)
			serial, err := e.Prove(t.Context(), root, query, nodes)
			runtime.GOMAXPROCS(4)
			if err != nil || len(serial.Proof.Nodes) <= 4 {
				t.Fatalf("serial deep proof: %d nodes, %v", len(serial.Proof.Nodes), err)
			}
			gated := &gatedProfile{Backend: backend, profile: profile, entered: make(chan string, 256), release: make(chan struct{})}
			parallelRegistry := tree.NewRegistry()
			if err = parallelRegistry.Register(gated); err != nil {
				t.Fatal(err)
			}
			parallelEngine := tree.New(parallelRegistry, derive)
			type outcome struct {
				result tree.Result
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := parallelEngine.Prove(t.Context(), root, query, nodes)
				done <- outcome{result, err}
			}()
			// All four vectors must enter Open before any of them is released.
			// The timeout only bounds a broken/deadlocked implementation.
			seen := map[string]bool{}
			for len(seen) < 4 {
				select {
				case key := <-gated.entered:
					seen[key] = true
				case <-time.After(10 * time.Second):
					close(gated.release)
					<-done
					t.Fatal("distinct vector openings did not overlap")
				}
			}
			close(gated.release)
			got := <-done
			if got.err != nil || gated.peak.Load() != 4 {
				t.Fatalf("parallel result: peak=%d error=%v", gated.peak.Load(), got.err)
			}
			serialBytes, _ := json.Marshal(serial)
			parallelBytes, _ := json.Marshal(got.result)
			if string(serialBytes) != string(parallelBytes) {
				t.Fatal("parallel scheduling changed ordered proof bytes")
			}
			if ok, err := e.Verify(root, query, got.result); err != nil || !ok {
				t.Fatalf("parallel evidence failed verification: %v", err)
			}
			ref, _, _ := maltcid.RootNode(root)
			if result, err := e.Prove(t.Context(), root, query, corruptChild{nodes, ref}); err == nil || len(result.Proof.Nodes) != 0 {
				t.Fatal("corrupt vector returned usable evidence")
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if _, err := e.Prove(ctx, root, query, nodes); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation was not preserved", err)
			}
		})
	}
}
