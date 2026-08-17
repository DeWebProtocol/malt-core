package mutation

import (
	"fmt"
	"slices"
	"strings"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	cid "github.com/ipfs/go-cid"
)

const ClientRootMaterializationProfile = "malt.client-root-materialization/v1"

// MapMaterialization carries the exact internal proof-serving state for one
// map transition output. Entries are implementation-owned radix cache paths,
// not logical map coordinates.
type MapMaterialization struct {
	TransitionID string
	Root         cid.Cid
	Entries      *arcset.CanonicalArcSet
}

// MapStateMaterialization carries root-bound proof-serving state for the
// complete map base included in a bootstrap writer result.
type MapStateMaterialization struct {
	Root    cid.Cid
	Entries *arcset.CanonicalArcSet
}

// ClientRootMaterialization carries root-bound proof-serving witnesses for
// every map output in one exact client-root bundle. List outputs are omitted
// until their tree materialization receives an equivalent witness profile.
type ClientRootMaterialization struct {
	Profile string
	Base    *MapStateMaterialization
	Maps    []MapMaterialization
}

// NewClientRootMaterialization validates and canonicalizes one witness against
// the exact transition/output identities in bundle.
func NewClientRootMaterialization(bundle ClientRootBundle, value ClientRootMaterialization) (ClientRootMaterialization, error) {
	canonicalBundle, err := NewClientRootBundle(bundle)
	if err != nil {
		return ClientRootMaterialization{}, err
	}
	if value.Profile != ClientRootMaterializationProfile {
		return ClientRootMaterialization{}, fmt.Errorf("client-root materialization profile must be %q", ClientRootMaterializationProfile)
	}
	var base *MapStateMaterialization
	if value.Base != nil {
		if !value.Base.Root.Defined() || !value.Base.Root.Equals(canonicalBundle.View.BaseRoot) {
			return ClientRootMaterialization{}, fmt.Errorf("base materialization root mismatch")
		}
		if len(canonicalBundle.View.Objects) != 1 {
			return ClientRootMaterialization{}, fmt.Errorf("base materialization requires a single-object bootstrap view")
		}
		object := canonicalBundle.View.Objects[0]
		if object.ObjectID != "root" || !object.Root.Equals(value.Base.Root) || object.Kind != arcset.KindMap || object.Entries == nil || object.Entries.Len() != 0 || object.Commit.FixedList != nil {
			return ClientRootMaterialization{}, fmt.Errorf("base materialization requires the canonical empty-map bootstrap object")
		}
		if value.Base.Entries == nil || value.Base.Entries.Kind() != arcset.KindMap {
			return ClientRootMaterialization{}, fmt.Errorf("base materialization entries must be a canonical map")
		}
		entries, err := arcset.NewCanonicalArcSet(arcset.KindMap, value.Base.Entries.Entries())
		if err != nil {
			return ClientRootMaterialization{}, fmt.Errorf("base materialization entries: %w", err)
		}
		base = &MapStateMaterialization{Root: value.Base.Root, Entries: entries}
	}
	outputByID := make(map[string]cid.Cid, len(canonicalBundle.Outputs))
	for _, output := range canonicalBundle.Outputs {
		outputByID[output.TransitionID] = output.Root
	}
	mapTransitions := make(map[string]struct{})
	for _, transition := range canonicalBundle.Intent.Transitions {
		if transition.Kind == arcset.KindMap {
			mapTransitions[transition.ID] = struct{}{}
		}
	}
	if len(value.Maps) != len(mapTransitions) {
		return ClientRootMaterialization{}, fmt.Errorf("client-root map materialization count mismatch")
	}
	maps := make([]MapMaterialization, len(value.Maps))
	seen := make(map[string]struct{}, len(value.Maps))
	for index, materialization := range value.Maps {
		if !validClientRootID(materialization.TransitionID) {
			return ClientRootMaterialization{}, fmt.Errorf("invalid materialization transition id %q", materialization.TransitionID)
		}
		if _, duplicate := seen[materialization.TransitionID]; duplicate {
			return ClientRootMaterialization{}, fmt.Errorf("duplicate materialization transition id %q", materialization.TransitionID)
		}
		seen[materialization.TransitionID] = struct{}{}
		if _, ok := mapTransitions[materialization.TransitionID]; !ok {
			return ClientRootMaterialization{}, fmt.Errorf("materialization transition %q is not a map output", materialization.TransitionID)
		}
		expectedRoot := outputByID[materialization.TransitionID]
		if !materialization.Root.Defined() || !materialization.Root.Equals(expectedRoot) {
			return ClientRootMaterialization{}, fmt.Errorf("materialization transition %q root mismatch", materialization.TransitionID)
		}
		if materialization.Entries == nil || materialization.Entries.Kind() != arcset.KindMap {
			return ClientRootMaterialization{}, fmt.Errorf("materialization transition %q entries must be a canonical map", materialization.TransitionID)
		}
		entries, err := arcset.NewCanonicalArcSet(arcset.KindMap, materialization.Entries.Entries())
		if err != nil {
			return ClientRootMaterialization{}, fmt.Errorf("materialization transition %q entries: %w", materialization.TransitionID, err)
		}
		maps[index] = MapMaterialization{TransitionID: materialization.TransitionID, Root: materialization.Root, Entries: entries}
	}
	slices.SortFunc(maps, func(a, b MapMaterialization) int { return strings.Compare(a.TransitionID, b.TransitionID) })
	return ClientRootMaterialization{Profile: ClientRootMaterializationProfile, Base: base, Maps: maps}, nil
}
