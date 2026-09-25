package object

import (
	"bytes"
	"context"
	"errors"
	"sort"

	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

// Block is an owned immutable content block, not an authentication vector.
type Block struct {
	CID   cid.Cid
	Bytes []byte
}

// Delta compares two locally committed graphs. Before is undefined on the first
// Commit. ArcSets are ordered children before parents and deduplicated by After.
// Blocks contains bytes for newly referenced, locally known content CIDs;
// External lists newly referenced CIDs without local bytes or an ArcSet writer.
// Both lists are deduplicated and sorted by CID bytes.
//
// These are write candidates relative to Before, not a statement about remote
// availability or a portable transition proof. There are no block deletions:
// old Roots and other references can still need previously referenced content.
type Delta struct {
	Before   cid.Cid
	After    cid.Cid
	ArcSets  []ArcSetDelta
	Blocks   []Block
	External []cid.Cid
}

// ArcSetDelta describes exact label additions, removals and target replacements
// for one vertex. Before is undefined when the vertex has no known version in
// the previous graph. A configuration change can change After with no Changes;
// the complete configurations are encoded in the Roots. Positional removals
// are explicit label deletions here, not authentication.Delta truncation syntax.
type ArcSetDelta struct {
	Before  cid.Cid
	After   cid.Cid
	Changes []engine.Change
	writer  *authentication.Writer
}

// Export produces a complete candidate only when requested. Previous identifies
// this graph delta's Before, even if the child was separately committed between
// the parent's two snapshots. The returned candidate owns its buffers.
func (d ArcSetDelta) Export(ctx context.Context) (protocol.AuthenticationCandidate, error) {
	if d.writer == nil || !d.After.Equals(d.writer.Root()) {
		return protocol.AuthenticationCandidate{}, errors.New("ArcSet delta has no matching retained writer")
	}
	if d.Before.Defined() && !maltcid.IsMaltCid(d.Before) {
		return protocol.AuthenticationCandidate{}, errors.New("ArcSet delta Before must be a MALT Root")
	}
	candidate, err := d.writer.Export(ctx)
	if err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	candidate.Previous = ""
	if d.Before.Defined() {
		candidate.Previous = d.Before.String()
	}
	return candidate, nil
}

type snapshotIndex struct {
	byCID map[string]*snapshot
	byID  map[*vertexID]*snapshot
}

func indexSnapshots(ctx context.Context, root *snapshot) (snapshotIndex, error) {
	out := snapshotIndex{byCID: make(map[string]*snapshot), byID: make(map[*vertexID]*snapshot)}
	seen := make(map[*snapshot]bool)
	stack := []*snapshot{root}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return snapshotIndex{}, err
		}
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n == nil || seen[n] {
			continue
		}
		seen[n] = true
		key := n.root.KeyString()
		// An opaque reference must not hide another vertex's local materialization.
		if old := out.byCID[key]; old == nil || n.writer != nil || n.block != nil {
			out.byCID[key] = n
		}
		if n.id != nil {
			out.byID[n.id] = n
		}
		stack = append(stack, n.children...)
	}
	return out, nil
}

func diffSnapshots(ctx context.Context, before, after *snapshot) (Delta, error) {
	if err := ctx.Err(); err != nil {
		return Delta{}, err
	}
	out := Delta{After: after.root}
	if before != nil {
		out.Before = before.root
		if before.root.Equals(after.root) {
			return out, nil
		}
	}
	old, err := indexSnapshots(ctx, before)
	if err != nil {
		return Delta{}, err
	}
	next, err := indexSnapshots(ctx, after)
	if err != nil {
		return Delta{}, err
	}
	visited := make(map[string]bool)
	active := make(map[string]bool)
	var visit func(*snapshot) error
	visit = func(n *snapshot) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := n.root.KeyString()
		if active[key] {
			return ErrCycle
		}
		if visited[key] {
			return nil
		}
		active[key] = true
		// Resolve CID-only references against all locally known vertices, so a
		// payload pointing at another new ArcSet also follows dependency order.
		n = next.byCID[key]
		for _, child := range n.children {
			if err := visit(child); err != nil {
				return err
			}
		}
		delete(active, key)
		visited[key] = true
		if n.writer == nil || old.byCID[key] != nil {
			return nil
		}
		change := ArcSetDelta{After: n.root, writer: n.writer}
		var previous []engine.Entry
		if base := old.byID[n.id]; base != nil && base.writer != nil {
			change.Before = base.root
			state, err := base.writer.State(ctx)
			if err != nil {
				return err
			}
			previous = state.Entries
		}
		state, err := n.writer.State(ctx)
		if err != nil {
			return err
		}
		change.Changes, err = diffEntries(ctx, previous, state.Entries)
		if err != nil {
			return err
		}
		out.ArcSets = append(out.ArcSets, change)
		return nil
	}
	if err := visit(after); err != nil {
		return Delta{}, err
	}
	keys := make([]string, 0, len(next.byCID))
	for key := range next.byCID {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return Delta{}, err
		}
		if old.byCID[key] != nil {
			continue
		}
		n := next.byCID[key]
		if n.block != nil {
			out.Blocks = append(out.Blocks, Block{CID: n.root, Bytes: bytes.Clone(n.block.Bytes)})
		} else if n.writer == nil {
			out.External = append(out.External, n.root)
		}
	}
	return out, nil
}

func diffEntries(ctx context.Context, before, after []engine.Entry) ([]engine.Change, error) {
	old := make(map[string]cid.Cid, len(before))
	for _, entry := range before {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		old[string(entry.Label)] = entry.Target
	}
	changes := make([]engine.Change, 0)
	for _, entry := range after {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		previous := old[string(entry.Label)]
		if !previous.Equals(entry.Target) {
			changes = append(changes, engine.Change{Label: bytes.Clone(entry.Label), Before: previous, After: entry.Target})
		}
		delete(old, string(entry.Label))
	}
	for label, target := range old {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		changes = append(changes, engine.Change{Label: []byte(label), Before: target})
	}
	sort.Slice(changes, func(i, j int) bool { return bytes.Compare(changes[i].Label, changes[j].Label) < 0 })
	return changes, nil
}
