package object

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

type authenticated struct {
	history
	engine *engine.Engine
	config CommitConfig
}

func newAuthenticated(e *engine.Engine, config CommitConfig, layout maltcid.Layout) (authenticated, error) {
	if err := checkConfig(e, config, layout); err != nil {
		return authenticated{}, err
	}
	return authenticated{history: newHistory(), engine: e, config: config}, nil
}

func checkConfig(e *engine.Engine, config CommitConfig, layout maltcid.Layout) error {
	if config.Content != (cid.Prefix{}) || config.Authentication.Layout != layout {
		return errors.New("object configuration does not match its authentication layout")
	}
	_, err := e.Interpret(engine.State{Descriptor: config.Authentication})
	return err
}

func (a *authenticated) commit(ctx context.Context, self Object, config CommitConfig, entries []engine.Entry, children []*snapshot) (*snapshot, error) {
	state := engine.State{Descriptor: config.Authentication, Entries: entries}
	var w *authentication.Writer
	var err error
	if a.after != nil && a.after.config == config {
		w, err = a.after.writer.Update(ctx, state)
	} else {
		w, err = authentication.BuildWriter(ctx, a.engine, state)
	}
	if err != nil {
		return nil, err
	}
	return a.stage(ctx, self, &snapshot{root: w.Root(), config: config, writer: w, children: children})
}

func (a *authenticated) retained() (*authentication.Writer, error) {
	if a.after == nil {
		return nil, ErrNotCommitted
	}
	return a.after.writer, nil
}

// Base supplies configuration, optional payload and retained authentication
// state for Prefix objects. Embed it in a struct and implement Commit by
// calling Base.CommitTagged(ctx, self); embedding alone cannot reflect fields
// of the outer Go struct.
type Base struct {
	authenticated
	payload cid.Cid
}

func NewBase(e *engine.Engine, config CommitConfig) (*Base, error) {
	a, err := newAuthenticated(e, config, maltcid.Prefix)
	if err != nil {
		return nil, err
	}
	return &Base{authenticated: a}, nil
}

func (b *Base) Payload() cid.Cid     { return b.payload }
func (b *Base) Config() CommitConfig { return b.config }

// CID is the last successful Commit result, or cid.Undef before Commit. It is
// not a claim that the current fields or descendants are unchanged.
func (b *Base) CID() cid.Cid { return b.cid() }

// Writer returns the last successful immutable writer. Keep it to retain that
// ArcSet version. Export its candidate for materialization, proving or transport.
// It contains this vertex's bindings, not its descendants' writers or bytes.
func (b *Base) Writer() (*authentication.Writer, error) { return b.retained() }

// Delta compares this vertex's last two successful committed graphs. A failed
// Commit preserves both snapshots. Returned labels and bytes belong to the caller.
func (b *Base) Delta(ctx context.Context) (Delta, error) { return b.delta(ctx) }

// SetPayload binds an already encoded content CID on the next Commit. Undef
// removes the binding; empty bytes instead have a defined content CID. Bytes
// and their storage stay with the caller.
func (b *Base) SetPayload(payload cid.Cid) { b.payload = payload }

// PayloadLabel is this SDK's reserved payload label for Prefix objects. With
// SHA256 derivation it is @payload. With Direct derivation it is the canonical
// SHA256-derived coordinate of @payload, used directly as a 32-byte label.
// This convention belongs to the object layer; auth assigns it no special meaning.
func PayloadLabel(config CommitConfig) ([]byte, error) {
	if config.Content != (cid.Prefix{}) || config.Authentication.Layout != maltcid.Prefix {
		return nil, errors.New("payload label requires a Prefix object")
	}
	switch derivation.ProfileID(config.Authentication.DerivationProfile) {
	case derivation.SHA256:
		return []byte("@payload"), nil
	case derivation.Direct:
		k, err := derivation.Derive(derivation.SHA256, []byte("@payload"))
		if err != nil {
			return nil, err
		}
		return coordinate.EncodeKey(k.Key), nil
	default:
		return nil, errors.New("unsupported object derivation profile")
	}
}

type reference struct {
	label  []byte
	target Object
}

func checkLabel(config CommitConfig, label []byte) error {
	if label == nil {
		return errors.New("label must be present; use an empty slice for an empty label")
	}
	k, err := derivation.Derive(derivation.ProfileID(config.Authentication.DerivationProfile), label)
	if err != nil {
		return err
	}
	if k.Kind != coordinate.Key {
		return errors.New("map label must derive a Prefix coordinate")
	}
	reserved, err := PayloadLabel(config)
	if err != nil {
		return err
	}
	if bytes.Equal(label, reserved) {
		return errors.New("payload label is reserved; use SetPayload")
	}
	return nil
}

func (b *Base) commitReferences(ctx context.Context, self Object, refs []reference) (*snapshot, error) {
	if b == nil {
		return nil, errors.New("object Base is nil")
	}
	config := self.Config()
	if err := checkConfig(b.engine, config, maltcid.Prefix); err != nil {
		return nil, err
	}
	// Validate the complete reference set before invoking any child Commit.
	seen := make(map[string]bool, len(refs))
	for _, r := range refs {
		if err := checkLabel(config, r.label); err != nil {
			return nil, fmt.Errorf("label %q: %w", r.label, err)
		}
		if err := checkObject(r.target); err != nil {
			return nil, fmt.Errorf("label %q: %w", r.label, err)
		}
		if seen[string(r.label)] {
			return nil, fmt.Errorf("duplicate label %q", r.label)
		}
		seen[string(r.label)] = true
	}
	sort.Slice(refs, func(i, j int) bool { return bytes.Compare(refs[i].label, refs[j].label) < 0 })
	entries := make([]engine.Entry, 0, len(refs)+1)
	children := make([]*snapshot, 0, len(refs)+1)
	for _, r := range refs {
		target, err := commitChild(ctx, r.target)
		if err != nil {
			return nil, fmt.Errorf("label %q: %w", r.label, err)
		}
		entries = append(entries, engine.Entry{Label: r.label, Target: target.root})
		children = append(children, target)
	}
	if payload := self.Payload(); payload.Defined() {
		label, err := PayloadLabel(config)
		if err != nil {
			return nil, err
		}
		entries = append(entries, engine.Entry{Label: label, Target: payload})
		children = append(children, &snapshot{root: payload})
	}
	return b.authenticated.commit(ctx, self, config, entries, children)
}
