package writer

import (
	"context"
	"crypto/sha256"
	"testing"

	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type checkpointCommitCounter struct {
	commitment.IndexCommitment
	commits int
}

func (c *checkpointCommitCounter) Commit(values []commitment.Cell) (cid.Cid, error) {
	c.commits++
	return c.IndexCommitment.Commit(values)
}

func (c *checkpointCommitCounter) ProveAtRoot(root cid.Cid, values []commitment.Cell, index uint64) (commitment.Cell, []byte, error) {
	return c.IndexCommitment.(commitment.IndexRootProver).ProveAtRoot(root, values, index)
}

func (c *checkpointCommitCounter) BatchProveAtRoot(
	root cid.Cid,
	values []commitment.Cell,
	indices []uint64,
) ([]commitment.Cell, []byte, error) {
	return c.IndexCommitment.(commitment.IndexRootProver).BatchProveAtRoot(root, values, indices)
}

func TestAuthenticatedCheckpointRestoresMaterializedWriterState(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, intent, expectedCandidate, _ := mapWriterFixture(t, ctx, scheme)
	store := materializermemory.New(true)
	runtime, err := NewRuntime(store, map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Load(ctx, view); err != nil {
		t.Fatal(err)
	}
	state, err := store.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	materializationDigest := sha256.Sum256([]byte("exact serialized materializer state"))
	key := []byte("0123456789abcdef0123456789abcdef")
	checkpoint, err := session.Checkpoint(materializationDigest, key)
	if err != nil {
		t.Fatal(err)
	}

	restoredStore, err := materializermemory.NewFromState(state)
	if err != nil {
		t.Fatal(err)
	}
	counter := &checkpointCommitCounter{IndexCommitment: scheme}
	restoredRuntime, err := NewRuntime(restoredStore, map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: counter,
	})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewSession(restoredRuntime)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.RestoreCheckpoint(ctx, checkpoint, key); err != nil {
		t.Fatal(err)
	}
	if counter.commits != 0 {
		t.Fatalf("RestoreCheckpoint replayed %d complete-vector commitments", counter.commits)
	}
	result, err := restored.Prepare(ctx, "checkpoint-restore", intent)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Bundle.Candidate.Equals(expectedCandidate) {
		t.Fatalf("restored candidate = %s, want %s", result.Bundle.Candidate, expectedCandidate)
	}
}

func TestAuthenticatedCheckpointRejectsWrongKeyAndMutatedBindings(t *testing.T) {
	ctx := context.Background()
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	view, _, _, _ := mapWriterFixture(t, ctx, scheme)
	runtime, err := NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{
		maltcid.BackendKindKZG: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSession(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Load(ctx, view); err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	checkpoint, err := session.Checkpoint(sha256.Sum256([]byte("state")), key)
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := NewSession(runtime)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.RestoreCheckpoint(ctx, checkpoint, []byte("fedcba9876543210fedcba9876543210")); err == nil {
		t.Fatal("checkpoint restored with the wrong key")
	}
	mutatedDigest := checkpoint
	mutatedDigest.MaterializationDigest[0] ^= 0xff
	if err := fresh.RestoreCheckpoint(ctx, mutatedDigest, key); err == nil {
		t.Fatal("checkpoint restored after materialization digest mutation")
	}
	mutatedRoots := checkpoint
	mutatedRoots.WorkingRoots = make(map[string]cid.Cid, len(checkpoint.WorkingRoots))
	for objectID, root := range checkpoint.WorkingRoots {
		mutatedRoots.WorkingRoots[objectID] = root
	}
	delete(mutatedRoots.WorkingRoots, "child")
	if err := fresh.RestoreCheckpoint(ctx, mutatedRoots, key); err == nil {
		t.Fatal("checkpoint restored with incomplete working roots")
	}
}
