package protocol

import (
	"fmt"

	malt "github.com/dewebprotocol/malt-core"
	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/proof/prooflist"
	cid "github.com/ipfs/go-cid"
)

const MapProofProfile = "malt.map-proof/v0alpha1"

// MapProofRequest is the serialized projection of one caller-selected map
// membership or non-membership request.
type MapProofRequest struct {
	Profile string   `json:"profile"`
	Root    string   `json:"root"`
	Key     []string `json:"key"`
}

// MapProofResult carries either a present target or an authenticated absence.
type MapProofResult struct {
	Profile   string              `json:"profile"`
	Present   bool                `json:"present"`
	Target    string              `json:"target,omitempty"`
	ProofList prooflist.ProofList `json:"prooflist"`
}

// MapProofVerification binds caller-selected root/key inputs to an untrusted
// membership or non-membership result.
type MapProofVerification struct {
	Request MapProofRequest `json:"request"`
	Result  MapProofResult  `json:"result"`
}

func NewMapProofRequest(request malt.MapProofRequest) (MapProofRequest, error) {
	if err := request.Validate(); err != nil {
		return MapProofRequest{}, err
	}
	path, err := malt.ParseSegmentPath(request.Key.String())
	if err != nil {
		return MapProofRequest{}, err
	}
	return MapProofRequest{Profile: MapProofProfile, Root: request.Root.String(), Key: path.Segments()}, nil
}

func (r MapProofRequest) Validate() error {
	if r.Profile != MapProofProfile {
		return fmt.Errorf("unsupported map-proof profile %q", r.Profile)
	}
	root, err := cid.Parse(r.Root)
	if err != nil {
		return fmt.Errorf("invalid map-proof root CID: %w", err)
	}
	if r.Key == nil || len(r.Key) == 0 {
		return fmt.Errorf("map-proof key field is required")
	}
	path, err := malt.NewSegmentPath(r.Key)
	if err != nil {
		return err
	}
	return (malt.MapProofRequest{Root: root, Key: arcset.CanonicalizePath(path.String())}).Validate()
}

func (r MapProofRequest) Core() (malt.MapProofRequest, error) {
	if err := r.Validate(); err != nil {
		return malt.MapProofRequest{}, err
	}
	root, _ := cid.Parse(r.Root)
	path, _ := malt.NewSegmentPath(r.Key)
	return malt.MapProofRequest{Root: root, Key: arcset.CanonicalizePath(path.String())}, nil
}

func NewMapProofResult(result malt.MapProofResult) (MapProofResult, error) {
	if !result.ProofList.Root.Defined() {
		return MapProofResult{}, fmt.Errorf("map-proof ProofList root is undefined")
	}
	value := MapProofResult{Profile: MapProofProfile, Present: result.Present, ProofList: result.ProofList}
	if result.Present {
		if !result.Target.Defined() {
			return MapProofResult{}, fmt.Errorf("present map-proof target is undefined")
		}
		value.Target = result.Target.String()
	} else if result.Target.Defined() {
		return MapProofResult{}, fmt.Errorf("absent map-proof target is defined")
	}
	if err := value.Validate(); err != nil {
		return MapProofResult{}, err
	}
	return value, nil
}

func (r MapProofResult) Validate() error {
	if r.Profile != MapProofProfile {
		return fmt.Errorf("unsupported map-proof result profile %q", r.Profile)
	}
	if r.Present {
		if _, err := cid.Parse(r.Target); err != nil {
			return fmt.Errorf("invalid present map-proof target CID: %w", err)
		}
	} else if r.Target != "" {
		return fmt.Errorf("absent map-proof result must not carry a target")
	}
	if !r.ProofList.Root.Defined() {
		return fmt.Errorf("map-proof ProofList root is undefined")
	}
	return r.ProofList.ValidateShape(prooflist.RequireSteps())
}

func (r MapProofResult) Core() (malt.MapProofResult, error) {
	if err := r.Validate(); err != nil {
		return malt.MapProofResult{}, err
	}
	target := cid.Undef
	if r.Present {
		target, _ = cid.Parse(r.Target)
	}
	return malt.MapProofResult{Present: r.Present, Target: target, ProofList: r.ProofList}, nil
}

func (v MapProofVerification) Validate() error {
	if err := v.Request.Validate(); err != nil {
		return err
	}
	return v.Result.Validate()
}
