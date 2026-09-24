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
	engine *engine.Engine
	config CommitConfig
	writer *authentication.Writer
}

func newAuthenticated(e *engine.Engine, config CommitConfig, layout maltcid.Layout) (authenticated, error) {
	if err := checkConfig(e, config, layout); err != nil {
		return authenticated{}, err
	}
	return authenticated{engine: e, config: config}, nil
}

func checkConfig(e *engine.Engine, config CommitConfig, layout maltcid.Layout) error {
	if config.Content != (cid.Prefix{}) || config.Authentication.Layout != layout {
		return errors.New("object configuration does not match its authentication layout")
	}
	_, err := e.Interpret(engine.State{Descriptor: config.Authentication})
	return err
}

func (a *authenticated) commit(ctx context.Context, config CommitConfig, entries []engine.Entry) (cid.Cid, error) {
	w, err := authentication.BuildWriter(ctx, a.engine, engine.State{Descriptor: config.Authentication, Entries: entries})
	if err != nil {
		return cid.Undef, err
	}
	if err := ctx.Err(); err != nil {
		return cid.Undef, err
	}
	a.writer = w
	return w.Root(), nil
}

func (a *authenticated) cid() cid.Cid {
	if a.writer == nil {
		return cid.Undef
	}
	return a.writer.Root()
}

func (a *authenticated) retained() (*authentication.Writer, error) {
	if a.writer == nil {
		return nil, ErrNotCommitted
	}
	return a.writer, nil
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

func (b *Base) commitReferences(ctx context.Context, self Object, refs []reference) (cid.Cid, error) {
	if b == nil {
		return cid.Undef, errors.New("object Base is nil")
	}
	config := self.Config()
	if err := checkConfig(b.engine, config, maltcid.Prefix); err != nil {
		return cid.Undef, err
	}
	// Validate the complete reference set before invoking any child Commit.
	seen := make(map[string]bool, len(refs))
	for _, r := range refs {
		if err := checkLabel(config, r.label); err != nil {
			return cid.Undef, fmt.Errorf("label %q: %w", r.label, err)
		}
		if err := checkObject(r.target); err != nil {
			return cid.Undef, fmt.Errorf("label %q: %w", r.label, err)
		}
		if seen[string(r.label)] {
			return cid.Undef, fmt.Errorf("duplicate label %q", r.label)
		}
		seen[string(r.label)] = true
	}
	sort.Slice(refs, func(i, j int) bool { return bytes.Compare(refs[i].label, refs[j].label) < 0 })
	entries := make([]engine.Entry, 0, len(refs)+1)
	for _, r := range refs {
		target, err := commitChild(ctx, r.target)
		if err != nil {
			return cid.Undef, fmt.Errorf("label %q: %w", r.label, err)
		}
		entries = append(entries, engine.Entry{Label: r.label, Target: target})
	}
	if payload := self.Payload(); payload.Defined() {
		label, err := PayloadLabel(config)
		if err != nil {
			return cid.Undef, err
		}
		entries = append(entries, engine.Entry{Label: label, Target: payload})
	}
	return b.authenticated.commit(ctx, config, entries)
}
