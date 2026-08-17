package protocol

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/mutation"
)

const (
	ClientRootMaterializationProfile    = mutation.ClientRootMaterializationProfile
	MaxClientRootMaterializationEntries = 1 << 22
)

// ClientRootMaterialization is the JSON projection of the root-bound
// proof-serving state exported by the browser writer.
type ClientRootMaterialization struct {
	Profile string                       `json:"profile"`
	Base    *MapStateMaterializationWire `json:"base,omitempty"`
	Maps    []MapMaterializationWire     `json:"maps"`
}

type MapStateMaterializationWire struct {
	Root    string                     `json:"root"`
	Entries []MaterializationEntryWire `json:"entries"`
}

type MapMaterializationWire struct {
	TransitionID string                     `json:"transition_id"`
	Root         string                     `json:"root"`
	Entries      []MaterializationEntryWire `json:"entries"`
}

type MaterializationEntryWire struct {
	Path string `json:"path"`
	CID  string `json:"cid"`
}

func NewClientRootMaterialization(bundle mutation.ClientRootBundle, value mutation.ClientRootMaterialization) (ClientRootMaterialization, error) {
	canonical, err := mutation.NewClientRootMaterialization(bundle, value)
	if err != nil {
		return ClientRootMaterialization{}, err
	}
	var base *MapStateMaterializationWire
	totalEntries := 0
	if canonical.Base != nil {
		entries := canonical.Base.Entries.Entries()
		totalEntries += len(entries)
		if totalEntries > MaxClientRootMaterializationEntries {
			return ClientRootMaterialization{}, fmt.Errorf("client-root materialization entry count exceeds %d", MaxClientRootMaterializationEntries)
		}
		wireEntries := make([]MaterializationEntryWire, len(entries))
		for index, entry := range entries {
			wireEntries[index] = MaterializationEntryWire{Path: entry.Coordinate.String(), CID: entry.Target.CID().String()}
		}
		base = &MapStateMaterializationWire{Root: canonical.Base.Root.String(), Entries: wireEntries}
	}
	maps := make([]MapMaterializationWire, len(canonical.Maps))
	for index, materialization := range canonical.Maps {
		entries := materialization.Entries.Entries()
		totalEntries += len(entries)
		if totalEntries > MaxClientRootMaterializationEntries {
			return ClientRootMaterialization{}, fmt.Errorf("client-root materialization entry count exceeds %d", MaxClientRootMaterializationEntries)
		}
		wireEntries := make([]MaterializationEntryWire, len(entries))
		for entryIndex, entry := range entries {
			wireEntries[entryIndex] = MaterializationEntryWire{
				Path: entry.Coordinate.String(), CID: entry.Target.CID().String(),
			}
		}
		maps[index] = MapMaterializationWire{
			TransitionID: materialization.TransitionID,
			Root:         materialization.Root.String(),
			Entries:      wireEntries,
		}
	}
	return ClientRootMaterialization{Profile: ClientRootMaterializationProfile, Base: base, Maps: maps}, nil
}

func (w ClientRootMaterialization) Core(bundle mutation.ClientRootBundle) (mutation.ClientRootMaterialization, error) {
	if w.Profile != ClientRootMaterializationProfile {
		return mutation.ClientRootMaterialization{}, fmt.Errorf("client-root materialization profile must be %q", ClientRootMaterializationProfile)
	}
	if len(w.Maps) > MaxClientRootTransitions {
		return mutation.ClientRootMaterialization{}, fmt.Errorf("client-root materialization map count exceeds %d", MaxClientRootTransitions)
	}
	var base *mutation.MapStateMaterialization
	totalEntries := 0
	if w.Base != nil {
		root, err := parseCanonicalCID(w.Base.Root, "base.root")
		if err != nil {
			return mutation.ClientRootMaterialization{}, err
		}
		totalEntries += len(w.Base.Entries)
		if totalEntries > MaxClientRootMaterializationEntries {
			return mutation.ClientRootMaterialization{}, fmt.Errorf("client-root materialization entry count exceeds %d", MaxClientRootMaterializationEntries)
		}
		entries, err := decodeMaterializationEntries("base", w.Base.Entries)
		if err != nil {
			return mutation.ClientRootMaterialization{}, err
		}
		base = &mutation.MapStateMaterialization{Root: root, Entries: entries}
	}
	maps := make([]mutation.MapMaterialization, len(w.Maps))
	for index, materialization := range w.Maps {
		root, err := parseCanonicalCID(materialization.Root, fmt.Sprintf("maps[%d].root", index))
		if err != nil {
			return mutation.ClientRootMaterialization{}, err
		}
		totalEntries += len(materialization.Entries)
		if totalEntries > MaxClientRootMaterializationEntries {
			return mutation.ClientRootMaterialization{}, fmt.Errorf("client-root materialization entry count exceeds %d", MaxClientRootMaterializationEntries)
		}
		entries, err := decodeMaterializationEntries(fmt.Sprintf("maps[%d]", index), materialization.Entries)
		if err != nil {
			return mutation.ClientRootMaterialization{}, err
		}
		maps[index] = mutation.MapMaterialization{
			TransitionID: materialization.TransitionID, Root: root, Entries: entries,
		}
	}
	return mutation.NewClientRootMaterialization(bundle, mutation.ClientRootMaterialization{Profile: w.Profile, Base: base, Maps: maps})
}

func decodeMaterializationEntries(label string, wire []MaterializationEntryWire) (*arcset.CanonicalArcSet, error) {
	entries := make([]arcset.ArcEntry, len(wire))
	for index, entry := range wire {
		if len(entry.Path) == 0 || len(entry.Path) > MaxClientRootPathBytes {
			return nil, fmt.Errorf("%s.entries[%d].path length is outside 1..%d", label, index, MaxClientRootPathBytes)
		}
		coordinate, err := arcset.NewMapCoordinate(entry.Path)
		if err != nil {
			return nil, fmt.Errorf("%s.entries[%d].path: %w", label, index, err)
		}
		if coordinate.String() != entry.Path {
			return nil, fmt.Errorf("%s.entries[%d].path is not canonical", label, index)
		}
		target, err := parseCanonicalCID(entry.CID, fmt.Sprintf("%s.entries[%d].cid", label, index))
		if err != nil {
			return nil, err
		}
		entries[index] = arcset.ArcEntry{Coordinate: coordinate, Target: arcset.NewUnknownTarget(target)}
	}
	canonical, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries)
	if err != nil {
		return nil, fmt.Errorf("%s.entries: %w", label, err)
	}
	if canonical.Len() != len(entries) {
		return nil, fmt.Errorf("%s.entries contain duplicate coordinates", label)
	}
	return canonical, nil
}

func (w ClientRootMaterialization) Validate(bundle mutation.ClientRootBundle) error {
	_, err := w.Core(bundle)
	return err
}
