// Package encoded adapts typed vectors to the existing CID-valued narrow
// materializer capabilities. It defines no durable storage or cache policy.
package encoded

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const NodePathPrefix = "runtime/auth/nodes/"

type Nodes struct {
	Lookup  materializer.Lookup
	Updater materializer.Updater
	Scope   string
}

func Paths(ref maltcid.NodeRef) ([]arcset.Path, error) {
	raw, err := ref.Bytes()
	if err != nil {
		return nil, err
	}
	p, err := maltcid.Profile(ref.Profile)
	if err != nil {
		return nil, err
	}
	base := NodePathPrefix + hex.EncodeToString(raw) + "/"
	paths := make([]arcset.Path, p.Slots+1)
	paths[0] = arcset.Path(base + "width")
	for i := 0; i < p.Slots; i++ {
		paths[i+1] = arcset.Path(base + "slots/" + strconv.Itoa(i))
	}
	return paths, nil
}
func carrier(data []byte) cid.Cid {
	sum, _ := mh.Encode(data, mh.IDENTITY)
	return cid.NewCidV1(cid.Raw, sum)
}
func parseCarrier(value cid.Cid) ([]byte, error) {
	if !value.Defined() || value.Version() != 1 || value.Prefix().Codec != cid.Raw {
		return nil, fmt.Errorf("invalid Cell carrier")
	}
	decoded, err := mh.Decode(value.Hash())
	if err != nil || decoded.Code != mh.IDENTITY {
		return nil, fmt.Errorf("Cell carrier requires identity bytes")
	}
	if !bytes.Equal(carrier(decoded.Digest).Bytes(), value.Bytes()) {
		return nil, fmt.Errorf("noncanonical Cell carrier")
	}
	return bytes.Clone(decoded.Digest), nil
}
func (n Nodes) GetNode(ctx context.Context, ref maltcid.NodeRef) ([]commitment.Cell, error) {
	if n.Lookup == nil {
		return nil, materializer.ErrIncomplete
	}
	paths, err := Paths(ref)
	if err != nil {
		return nil, err
	}
	values, err := n.Lookup.BatchGet(ctx, n.Scope, cid.Undef, paths)
	if err != nil {
		return nil, err
	}
	allowed := make(map[arcset.Path]bool, len(paths))
	for _, path := range paths {
		allowed[path] = true
	}
	for path := range values {
		if !allowed[path] {
			return nil, fmt.Errorf("unexpected node coordinate %q", path)
		}
	}
	width, ok := values[paths[0]]
	if !ok {
		return nil, materializer.ErrIncomplete
	}
	raw, err := parseCarrier(width)
	if err != nil {
		return nil, err
	}
	w, count := binary.Uvarint(raw)
	if count <= 0 || w != uint64(len(paths)-1) || !bytes.Equal(binary.AppendUvarint(nil, w), raw) {
		return nil, fmt.Errorf("invalid node width marker")
	}
	cells := make([]commitment.Cell, len(paths)-1)
	for i, path := range paths[1:] {
		if value, ok := values[path]; ok {
			cells[i], err = parseCarrier(value)
			if err != nil {
				return nil, err
			}
			if len(cells[i]) == 0 {
				return nil, fmt.Errorf("explicit empty Cell is noncanonical")
			}
		}
	}
	return cells, nil
}
func (n Nodes) PutNode(ctx context.Context, ref maltcid.NodeRef, cells []commitment.Cell) error {
	if n.Updater == nil {
		return fmt.Errorf("node updater is nil")
	}
	paths, err := Paths(ref)
	if err != nil {
		return err
	}
	if len(cells) != len(paths)-1 {
		return fmt.Errorf("node vector width mismatch")
	}
	values := map[arcset.Path]cid.Cid{paths[0]: carrier(binary.AppendUvarint(nil, uint64(len(cells))))}
	for i, cell := range cells {
		if len(cell) > 0 {
			values[paths[i+1]] = carrier(cell)
		}
	}
	arcs, err := arcset.NewArcSetFromPaths(values)
	if err != nil {
		return err
	}
	if rooted, ok := n.Updater.(materializer.RootedNodeUpdater); ok {
		raw, _ := ref.Bytes()
		return rooted.UpdateNode(ctx, n.Scope, carrier(raw), arcs)
	}
	return n.Updater.Update(ctx, n.Scope, cid.Undef, cid.Undef, arcs)
}

// Identity is the internal-node CID carrier used to own an internal vector. It
// carries NodeRef bytes and cannot be parsed as an external MALT Root.
func Identity(ref maltcid.NodeRef) (cid.Cid, error) {
	raw, err := ref.Bytes()
	if err != nil {
		return cid.Undef, err
	}
	return carrier(raw), nil
}
func RootIdentity(root cid.Cid) (cid.Cid, error) {
	ref, _, err := maltcid.RootNode(root)
	if err != nil {
		return cid.Undef, err
	}
	return Identity(ref)
}
func References(value cid.Cid) []cid.Cid {
	raw, err := parseCarrier(value)
	if err != nil {
		return nil
	}
	ref, target, err := maltcid.CellReference(raw)
	if err != nil {
		return nil
	}
	if ref != nil {
		identity, err := Identity(*ref)
		if err == nil {
			return []cid.Cid{identity}
		}
	}
	if target.Defined() {
		return []cid.Cid{target}
	}
	return nil
}

// ParseIdentity decodes an internal-node carrier; application Roots use
// maltcid.ParseRoot instead.
func ParseIdentity(value cid.Cid) (maltcid.NodeRef, error) {
	data, err := parseCarrier(value)
	if err != nil {
		return maltcid.NodeRef{}, err
	}
	return maltcid.ParseNodeRef(data)
}

// MatchPaths recognizes the complete canonical vector lookup, including its
// presence/width marker. Backends may use it to key materialization caches.
func MatchPaths(paths []arcset.Path) (maltcid.NodeRef, bool) {
	if len(paths) == 0 {
		return maltcid.NodeRef{}, false
	}
	first := paths[0].String()
	if !strings.HasPrefix(first, NodePathPrefix) || !strings.HasSuffix(first, "/width") {
		return maltcid.NodeRef{}, false
	}
	raw, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(first, NodePathPrefix), "/width"))
	if err != nil {
		return maltcid.NodeRef{}, false
	}
	ref, err := maltcid.ParseNodeRef(raw)
	if err != nil {
		return ref, false
	}
	expected, err := Paths(ref)
	if err != nil || len(expected) != len(paths) {
		return ref, false
	}
	for i, path := range paths {
		if path != expected[i] {
			return ref, false
		}
	}
	return ref, true
}
