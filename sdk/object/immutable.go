package object

import (
	"bytes"
	"context"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

// Immutable is an immutable raw-byte leaf. Its payload and committed CID are
// the same ordinary CIDv1(raw, sha2-256). It has no outgoing references.
// Other immutable encodings can implement Object directly.
type Immutable struct {
	history
	data []byte
	root cid.Cid
}

func rawConfig() CommitConfig {
	return CommitConfig{Content: cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}}
}

// NewImmutable copies the bytes. An empty payload is a valid immutable block,
// distinct from the absence of a payload on another Object.
func NewImmutable(data []byte) (*Immutable, error) {
	data = bytes.Clone(data)
	root, err := rawConfig().Content.Sum(data)
	if err != nil {
		return nil, err
	}
	return &Immutable{history: newHistory(), data: data, root: root}, nil
}

func (o *Immutable) Payload() cid.Cid     { return o.root }
func (o *Immutable) Config() CommitConfig { return rawConfig() }

// Bytes returns a copy for caller-owned storage or transport.
func (o *Immutable) Bytes() []byte { return bytes.Clone(o.data) }

// Delta returns the block on the first successful Commit and an empty content
// delta on subsequent Commits of this immutable value.
func (o *Immutable) Delta(ctx context.Context) (Delta, error) { return o.delta(ctx) }

func (o *Immutable) Commit(ctx context.Context) (cid.Cid, error) {
	return withCommit(ctx, o, func(ctx context.Context) (*snapshot, error) {
		return o.stage(ctx, o, &snapshot{
			root: o.root, config: o.Config(), block: &Block{CID: o.root, Bytes: o.data},
		})
	})
}
