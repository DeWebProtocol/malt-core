// Package hashtrie implements an experimental compact SHA-256 Patricia tree
// over complete typed coordinates and CID targets. Its roots and proofs are
// independent of MALT Root/ProofList formats and cannot enter native verification.
// Persistence remains caller-owned through the existing narrow materializer.
package hashtrie

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const RootSchema = "malt-experimental/hashtrie-root/v1"
const ProofSchema = "malt-experimental/hashtrie-proof/v1"
const NodePathPrefix = "experimental/auth/hashtrie/v1/"

type Digest [32]byte
type Root struct {
	Schema string          `json:"schema"`
	Kind   coordinate.Kind `json:"kind"`
	Digest Digest          `json:"digest"`
}
type Entry struct {
	Coordinate coordinate.Coordinate
	Target     cid.Cid
}
type Change struct {
	Coordinate    coordinate.Coordinate
	Before, After cid.Cid
}
type Step struct {
	Split   uint16 `json:"split"`
	Prefix  Digest `json:"prefix"`
	Sibling Digest `json:"sibling"`
}
type Proof struct {
	Schema   string `json:"schema"`
	Key      []byte `json:"coordinate"`
	Steps    []Step `json:"steps"`
	Terminal []byte `json:"terminal"`
}
type Result struct {
	Present bool
	Target  cid.Cid
}

// Nodes adapts experimental node bodies to the same CID-valued ArcSet
// materializer used by encoded native vectors. It defines no backend or cache.
type Nodes struct {
	Lookup  materializer.Lookup
	Updater materializer.Updater
	Scope   string
}

func kindTag(kind coordinate.Kind) (byte, error) {
	switch kind {
	case coordinate.Key:
		return 1, nil
	case coordinate.Index:
		return 2, nil
	}
	return 0, fmt.Errorf("invalid coordinate kind")
}
func newRoot(kind coordinate.Kind, digest Digest) Root { return Root{RootSchema, kind, digest} }
func (r Root) Validate() error {
	if r.Schema != RootSchema {
		return fmt.Errorf("experimental root schema required")
	}
	_, err := kindTag(r.Kind)
	return err
}
func (r Root) Reference() (cid.Cid, error) {
	if err := r.Validate(); err != nil {
		return cid.Undef, err
	}
	tag, _ := kindTag(r.Kind)
	body := append([]byte("malt-experimental/hashtrie-root/v1\x00"), tag)
	body = append(body, r.Digest[:]...)
	hash, _ := mh.Encode(body, mh.IDENTITY)
	return cid.NewCidV1(cid.Raw, hash), nil
}
func carrier(body []byte) cid.Cid {
	hash, _ := mh.Encode(body, mh.IDENTITY)
	return cid.NewCidV1(cid.Raw, hash)
}
func decodeCarrier(value cid.Cid) ([]byte, error) {
	if !value.Defined() || value.Version() != 1 || value.Type() != cid.Raw {
		return nil, fmt.Errorf("experimental node requires an identity carrier")
	}
	decoded, err := mh.Decode(value.Hash())
	if err != nil || decoded.Code != mh.IDENTITY || len(decoded.Digest) > 8192 || !bytes.Equal(carrier(decoded.Digest).Bytes(), value.Bytes()) {
		return nil, fmt.Errorf("invalid experimental node carrier")
	}
	return bytes.Clone(decoded.Digest), nil
}
func nodePath(root Root) arcset.Path {
	return arcset.Path(NodePathPrefix + string(root.Kind) + "/" + hex.EncodeToString(root.Digest[:]) + "/body")
}
func hashNode(body []byte) Digest {
	hash := sha256.New()
	hash.Write([]byte("malt-experimental/hashtrie-node/v1\x00"))
	hash.Write(body)
	var d Digest
	copy(d[:], hash.Sum(nil))
	return d
}
func empty(kind coordinate.Kind) Digest { tag, _ := kindTag(kind); return hashNode([]byte{0, tag}) }
func route(kind coordinate.Kind, key []byte) Digest {
	hash := sha256.New()
	hash.Write([]byte("malt-experimental/hashtrie-route/v1\x00"))
	tag, _ := kindTag(kind)
	hash.Write([]byte{tag})
	hash.Write(key)
	var d Digest
	copy(d[:], hash.Sum(nil))
	return d
}
func bit(key Digest, index uint16) byte { return (key[index/8] >> (7 - index%8)) & 1 }
func prefix(key Digest, bits uint16) Digest {
	out := key
	for i := int(bits); i < 256; i++ {
		out[i/8] &= ^(byte(1) << (7 - uint(i%8)))
	}
	return out
}
func shared(a, b Digest) uint16 {
	for i := uint16(0); i < 256; i++ {
		if bit(a, i) != bit(b, i) {
			return i
		}
	}
	return 256
}
func key(kind coordinate.Kind, c coordinate.Coordinate) ([]byte, error) {
	if c.Kind != kind {
		return nil, fmt.Errorf("query coordinate kind differs from root")
	}
	return c.Encode()
}

type node struct {
	leaf                bool
	key                 []byte
	target              cid.Cid
	split               uint16
	prefix, left, right Digest
}

func leafBody(kind coordinate.Kind, key []byte, target cid.Cid) ([]byte, error) {
	if !target.Defined() || len(target.Bytes()) > 4096 {
		return nil, fmt.Errorf("defined bounded complete target CID required")
	}
	tag, err := kindTag(kind)
	if err != nil {
		return nil, err
	}
	body := []byte{1, tag}
	body = binary.BigEndian.AppendUint16(body, uint16(len(key)))
	body = append(body, key...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(target.Bytes())))
	body = append(body, target.Bytes()...)
	return body, nil
}
func branchBody(kind coordinate.Kind, split uint16, p, left, right Digest) ([]byte, error) {
	if split >= 256 || prefix(p, split) != p || left == empty(kind) || right == empty(kind) {
		return nil, fmt.Errorf("noncanonical compact branch")
	}
	tag, err := kindTag(kind)
	if err != nil {
		return nil, err
	}
	body := binary.BigEndian.AppendUint16([]byte{2, tag}, split)
	body = append(body, p[:]...)
	body = append(body, left[:]...)
	body = append(body, right[:]...)
	return body, nil
}
func parse(kind coordinate.Kind, body []byte) (node, error) {
	var n node
	tag, err := kindTag(kind)
	if err != nil || len(body) < 2 || body[1] != tag {
		return n, fmt.Errorf("node kind/header mismatch")
	}
	if body[0] == 1 {
		if len(body) < 6 {
			return n, fmt.Errorf("truncated leaf")
		}
		size := int(binary.BigEndian.Uint16(body[2:4]))
		if size+6 > len(body) {
			return n, fmt.Errorf("invalid coordinate length")
		}
		n.key = bytes.Clone(body[4 : 4+size])
		c, err := coordinate.Parse(n.key)
		if err != nil || c.Kind != kind {
			return n, fmt.Errorf("noncanonical full coordinate")
		}
		targetSize := int(binary.BigEndian.Uint16(body[4+size : 6+size]))
		if targetSize == 0 || targetSize > 4096 || size+6+targetSize != len(body) {
			return n, fmt.Errorf("invalid complete CID length")
		}
		n.target, err = cid.Cast(body[6+size:])
		if err != nil {
			return n, err
		}
		n.leaf = true
		canonical, err := leafBody(kind, n.key, n.target)
		if err != nil || !bytes.Equal(body, canonical) {
			return n, fmt.Errorf("noncanonical leaf")
		}
		return n, nil
	}
	if body[0] != 2 || len(body) != 100 {
		return n, fmt.Errorf("invalid compact node type or length")
	}
	n.split = binary.BigEndian.Uint16(body[2:4])
	copy(n.prefix[:], body[4:36])
	copy(n.left[:], body[36:68])
	copy(n.right[:], body[68:100])
	canonical, err := branchBody(kind, n.split, n.prefix, n.left, n.right)
	if err != nil || !bytes.Equal(body, canonical) {
		return n, fmt.Errorf("noncanonical branch")
	}
	return n, nil
}
func (s Nodes) put(ctx context.Context, kind coordinate.Kind, body []byte) (Digest, error) {
	if err := ctx.Err(); err != nil {
		return Digest{}, err
	}
	if s.Updater == nil {
		return Digest{}, fmt.Errorf("node updater unavailable")
	}
	digest := hashNode(body)
	r := newRoot(kind, digest)
	arcs, err := arcset.NewArcSetFromPaths(map[arcset.Path]cid.Cid{nodePath(r): carrier(body)})
	if err != nil {
		return Digest{}, err
	}
	if rooted, ok := s.Updater.(materializer.RootedNodeUpdater); ok {
		owner, _ := r.Reference()
		err = rooted.UpdateNode(ctx, s.Scope, owner, arcs)
	} else {
		err = s.Updater.Update(ctx, s.Scope, cid.Undef, cid.Undef, arcs)
	}
	return digest, err
}
func (s Nodes) get(ctx context.Context, kind coordinate.Kind, digest Digest) (node, []byte, error) {
	if s.Lookup == nil {
		return node{}, nil, materializer.ErrIncomplete
	}
	if err := ctx.Err(); err != nil {
		return node{}, nil, err
	}
	value, err := s.Lookup.Get(ctx, s.Scope, cid.Undef, nodePath(newRoot(kind, digest)))
	if materializer.IsNotFound(err) {
		return node{}, nil, materializer.ErrIncomplete
	}
	if err != nil {
		return node{}, nil, err
	}
	body, err := decodeCarrier(value)
	if err != nil {
		return node{}, nil, err
	}
	if hashNode(body) != digest {
		return node{}, nil, fmt.Errorf("untrusted node body does not match root-relative digest")
	}
	n, err := parse(kind, body)
	return n, body, err
}
