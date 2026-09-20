package tree

import (
	"context"
	"errors"
	"math"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

var ErrNotMeasured = errors.New("Positional state has no byte measurements")

type RangeResult struct {
	Metadata         Metadata `json:"metadata"`
	MetadataEvidence Result   `json:"metadata_evidence"`
	Segments         []Result `json:"segments"`
}

// ReadMetadata uses the always-out-of-range uint64 maximum index to obtain a
// root metadata opening. Metadata stays structural: there is no system arc.
func (e *Engine) ReadMetadata(ctx context.Context, root cid.Cid, source materializer.NodeLookup) (Metadata, Result, error) {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return Metadata{}, Result{}, err
	}
	if d.Layout != maltcid.Positional {
		return Metadata{}, Result{}, errors.New("metadata requires Positional")
	}
	result, err := e.Prove(ctx, root, coordinate.At(math.MaxUint64), source)
	if err != nil {
		return Metadata{}, Result{}, err
	}
	meta, err := parseMetadata(result.Proof.Nodes[0].Metadata)
	return meta, result, err
}
func rangeBounds(meta Metadata, start uint64, end *uint64) (uint64, uint64, error) {
	if meta.ChunkSize == 0 {
		return 0, 0, ErrNotMeasured
	}
	stop := meta.TotalSize
	if end != nil {
		stop = *end
	}
	if start > stop || stop > meta.TotalSize {
		return 0, 0, errors.New("byte range is outside authenticated length")
	}
	if start == stop {
		return 0, 0, nil
	}
	first := start / meta.ChunkSize
	count := (stop-1)/meta.ChunkSize - first + 1
	return first, count, nil
}
func (e *Engine) ProveRange(ctx context.Context, root cid.Cid, start uint64, end *uint64, source materializer.NodeLookup) (RangeResult, error) {
	meta, evidence, err := e.ReadMetadata(ctx, root, source)
	if err != nil {
		return RangeResult{}, err
	}
	first, count, err := rangeBounds(meta, start, end)
	if err != nil {
		return RangeResult{}, err
	}
	result := RangeResult{Metadata: meta, MetadataEvidence: evidence, Segments: []Result{}}
	for offset := uint64(0); offset < count; offset++ {
		segment, err := e.Prove(ctx, root, coordinate.At(first+offset), source)
		if err != nil {
			return RangeResult{}, err
		}
		if !segment.Present {
			return RangeResult{}, errors.New("missing in-range segment")
		}
		result.Segments = append(result.Segments, segment)
	}
	return result, nil
}
func (e *Engine) VerifyRange(root cid.Cid, start uint64, end *uint64, result RangeResult) (bool, error) {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return false, err
	}
	if d.Layout != maltcid.Positional {
		return false, errors.New("range requires Positional")
	}
	valid, err := e.Verify(root, coordinate.At(math.MaxUint64), result.MetadataEvidence)
	if err != nil || !valid {
		return valid, err
	}
	meta, err := parseMetadata(result.MetadataEvidence.Proof.Nodes[0].Metadata)
	if err != nil {
		return false, err
	}
	if result.Metadata != meta {
		return false, nil
	}
	first, count, err := rangeBounds(meta, start, end)
	if err != nil {
		return false, err
	}
	if uint64(len(result.Segments)) != count {
		return false, nil
	}
	for offset, segment := range result.Segments {
		if !segment.Present {
			return false, nil
		}
		valid, err := e.Verify(root, coordinate.At(first+uint64(offset)), segment)
		if err != nil || !valid {
			return valid, err
		}
	}
	return true, nil
}
