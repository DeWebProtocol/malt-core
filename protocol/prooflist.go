package protocol

import (
	"errors"
	"fmt"
	"math"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/auth/tree"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/internal/proofwire"
	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

// ProofListMediaType selects the compact binary projection of a typed query result.
const ProofListMediaType = "application/vnd.malt.prooflist.v1"

// EncodeProofList serializes untrusted evidence against the exact original
// request. It checks reconstructible fields, without doing a prover self-check.
func EncodeProofList(q AuthenticationRequest, r AuthenticationResult) ([]byte, error) {
	s := new(proofwire.Stream)
	if err := transferProofList(s, q, &r); err != nil {
		return nil, err
	}
	return s.Data, nil
}

// DecodeProofList restores the typed result for local verification. Successful
// decoding never authenticates a target, an absence, or a List count.
func DecodeProofList(q AuthenticationRequest, data []byte) (AuthenticationResult, error) {
	if len(data) == 0 || len(data) > proofwire.MaxBytes {
		return AuthenticationResult{}, errors.New("invalid ProofList size")
	}
	s := &proofwire.Stream{Reading: true, Data: data}
	var r AuthenticationResult
	if err := transferProofList(s, q, &r); err != nil {
		return AuthenticationResult{}, err
	}
	if len(s.Data) != 0 {
		return AuthenticationResult{}, errors.New("trailing ProofList bytes")
	}
	return r, nil
}

func transferProofList(s *proofwire.Stream, q AuthenticationRequest, r *AuthenticationResult) error {
	if err := q.Validate(); err != nil {
		return err
	}
	if !s.Reading && r.Profile != q.Profile {
		return errors.New("incorrect ProofList result profile")
	}
	r.Profile = q.Profile
	current, _ := cid.Decode(q.Root)
	var status uint64
	if r.AbsentStep != nil {
		status = 1
	}
	status = s.Uint(status)
	count := len(q.Steps)
	switch status {
	case 0:
	case 1:
		var at uint64
		if r.AbsentStep != nil {
			at = *r.AbsentStep
		}
		at = s.Uint(at)
		if at >= uint64(count) {
			return errors.New("invalid absent step")
		}
		count = int(at) + 1
		r.AbsentStep = &at
	default:
		return errors.New("invalid ProofList outcome")
	}
	if s.Err != nil {
		return s.Err
	}
	if s.Reading {
		r.Traversal.Results = make([]engine.Result, count)
	} else if len(r.Traversal.Results) != count {
		return errors.New("incorrect ProofList step count")
	}
	for i := 0; i < count; i++ {
		present := status == 0 || i < count-1
		item := r.Traversal.Results[i]
		if err := transferResult(s, current, q.Steps[i], present, &item, nil); err != nil {
			return fmt.Errorf("step %d: %w", i, err)
		}
		current = item.Target
		if s.Reading {
			r.Traversal.Results[i] = item
		}
	}
	if status == 1 {
		if r.Resolved != "" || r.Binding != nil || r.Range != nil {
			return errors.New("unexpected result after absent traversal")
		}
		return nil
	}
	if !s.Reading {
		selected, err := cid.Decode(r.Resolved)
		if err != nil || !current.Equals(selected) {
			return errors.New("resolved CID disagrees with traversal")
		}
	}
	r.Resolved = current.String()
	switch q.Operation {
	case "resolve":
		if r.Binding != nil || r.Range != nil {
			return errors.New("unexpected primitive in resolve result")
		}
	case "binding":
		if s.Reading {
			r.Binding = new(engine.Result)
		}
		if r.Binding == nil || r.Range != nil {
			return errors.New("missing or ambiguous binding result")
		}
		// Work on a copy when encoding so concurrent readers can reuse the result.
		item := *r.Binding
		present, err := transferPresence(s, item.Present)
		if err != nil {
			return err
		}
		if err = transferResult(s, current, *q.Label, present, &item, nil); err != nil {
			return err
		}
		if s.Reading {
			*r.Binding = item
		}
	case "range":
		if s.Reading {
			r.Range = new(engine.RangeResult)
		}
		if r.Range == nil || r.Binding != nil {
			return errors.New("missing or ambiguous range result")
		}
		item := *r.Range
		if err := transferRange(s, current, q, &item); err != nil {
			return err
		}
		if s.Reading {
			*r.Range = item
		}
	}
	return s.Err
}

func transferPresence(s *proofwire.Stream, present bool) (bool, error) {
	var tag uint64
	if present {
		tag = 1
	}
	tag = s.Uint(tag)
	if tag > 1 {
		return false, errors.New("invalid binding outcome")
	}
	return tag == 1, s.Err
}

func transferResult(s *proofwire.Stream, root cid.Cid, label []byte, present bool, item *engine.Result, shared *tree.NodeOpening) error {
	if !s.Reading && (item.Present != present || item.Target.Defined() != present) {
		return errors.New("inconsistent binding outcome")
	}
	item.Present = present
	if present {
		item.Target = s.CID(item.Target)
	}
	if s.Err != nil {
		return s.Err
	}
	return transferBinding(s, root, label, item, shared)
}

func transferBinding(s *proofwire.Stream, root cid.Cid, label []byte, item *engine.Result, shared *tree.NodeOpening) error {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil {
		return err
	}
	if label == nil || (d.Layout == maltcid.List && d.DerivationProfile != uint8(derivation.Direct)) {
		return errors.New("invalid label or List derivation")
	}
	key, err := derivation.Derive(derivation.ProfileID(d.DerivationProfile), label)
	if err != nil {
		return err
	}
	return tree.TransferBindingProof(s, d, tree.Selector{Coordinate: key, Label: label}, item.Target, &item.Proof, shared)
}

// EncodeBindingProof returns the compact step evidence given the external Root,
// label and binding outcome. The returned bytes exclude that outcome and target.
func EncodeBindingProof(root cid.Cid, label []byte, result engine.Result) ([]byte, error) {
	if result.Present != result.Target.Defined() {
		return nil, errors.New("inconsistent binding outcome")
	}
	s := new(proofwire.Stream)
	if err := transferBinding(s, root, label, &result, nil); err != nil {
		return nil, err
	}
	return s.Data, nil
}

func transferRange(s *proofwire.Stream, root cid.Cid, q AuthenticationRequest, r *engine.RangeResult) error {
	d, _, err := maltcid.ParseRoot(root)
	if err != nil || d.Layout != maltcid.List {
		return errors.New("range requires List root")
	}
	if err := transferResult(s, root, coordinate.EncodeIndex(math.MaxUint64), false, &r.MetadataEvidence, nil); err != nil {
		return err
	}
	meta, err := r.MetadataEvidence.Proof.RootMetadata()
	if err != nil {
		return err
	}
	if !s.Reading && r.Metadata != meta {
		return errors.New("range metadata disagrees with opening")
	}
	r.Metadata = meta
	end := meta.Count
	if q.End != nil {
		end = *q.End
	}
	if *q.Start > end || end > meta.Count {
		return errors.New("range outside List bounds")
	}
	count := end - *q.Start
	shared := &r.MetadataEvidence.Proof.Nodes[0]
	// Bound logical metadata work as well as the wire size. The public result
	// may be projected to JSON or verified by consumers that visit every segment.
	if count > uint64(proofwire.MaxBytes)/uint64(len(shared.Metadata)+len(shared.MetadataProof)) {
		return errors.New("expanded range metadata exceeds proof limit")
	}
	if s.Reading {
		if count > uint64(len(s.Data)) {
			return errors.New("truncated range segments")
		}
		r.Segments = []engine.Result{}
	} else if uint64(len(r.Segments)) != count {
		return errors.New("incorrect range segment count")
	}
	for i := uint64(0); i < count; i++ {
		var item engine.Result
		if !s.Reading {
			item = r.Segments[i]
		}
		present, err := transferPresence(s, item.Present)
		if err != nil {
			return err
		}
		if err = transferResult(s, root, coordinate.EncodeIndex(*q.Start+i), present, &item, shared); err != nil {
			return err
		}
		if s.Reading {
			r.Segments = append(r.Segments, item)
		}
	}
	return s.Err
}
