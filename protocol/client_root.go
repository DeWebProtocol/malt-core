package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	// Client-root wire profiles are aliases of the transport-neutral core
	// profiles. Keeping the literals owned by mutation prevents profile drift
	// between in-process and serialized contracts.
	UpdateViewProfile             = mutation.UpdateViewProfile
	SemanticIntentProfile         = mutation.SemanticIntentProfile
	ClientRootBundleProfile       = mutation.ClientRootBundleProfile
	MaterializationReceiptProfile = mutation.MaterializationReceiptProfile

	StatefulCompleteVectorsProfile = mutation.StatefulCompleteVectorsProfile

	PresenceAbsent  Presence = "absent"
	PresencePresent Presence = "present"

	CommitModeDefault   CommitMode = "default"
	CommitModeFixedList CommitMode = "fixed_list"

	// These hard limits bound allocations and graph walks independently from
	// caller-supplied update-view bounds. They are wire safety ceilings, not
	// benchmark workload defaults.
	MaxClientRootObjects     = 1 << 16
	MaxClientRootEntries     = 1 << 20
	MaxClientRootDepth       = 1 << 16
	MaxClientRootTransitions = 1 << 16
	MaxClientRootChanges     = 1 << 20
	MaxClientRootPayloadCIDs = 1 << 20
	MaxClientRootCIDBytes    = 4096
	MaxClientRootPathBytes   = 4096
)

// Presence makes optional wire values explicit. An absent value has empty
// companion fields; a present value must carry all companion fields.
type Presence string

// CommitMode distinguishes the default semantic commit from the measured
// fixed-list commit without relying on a nullable object.
type CommitMode string

// UpdateView is the JSON projection of mutation.UpdateView.
type UpdateView struct {
	Profile      string           `json:"profile"`
	StateProfile string           `json:"state_profile"`
	BaseRoot     string           `json:"base_root"`
	Bounds       UpdateViewBounds `json:"bounds"`
	Objects      []UpdateObject   `json:"objects"`
}

type UpdateViewBounds struct {
	MaxObjects      uint32 `json:"max_objects"`
	MaxTotalEntries uint64 `json:"max_total_entries"`
	MaxDepth        uint32 `json:"max_depth"`
}

type UpdateObject struct {
	ObjectID string           `json:"object_id"`
	Root     string           `json:"root"`
	Kind     arcset.Kind      `json:"kind"`
	Entries  []ArcEntry       `json:"entries"`
	Commit   CommitDescriptor `json:"commit"`
}

// ArcEntry binds one explicitly typed coordinate to one explicitly typed CID.
type ArcEntry struct {
	Coordinate Coordinate `json:"coordinate"`
	Target     Target     `json:"target"`
}

// Coordinate always serializes all fields. For a map coordinate, MapPath is
// canonical and ListIndex is zero. For a list coordinate, MapPath is empty and
// ListIndex is the full uint64 index. Kind is checked against the containing
// object rather than inferred from either zero value.
type Coordinate struct {
	Kind      arcset.Kind `json:"kind"`
	MapPath   string      `json:"map_path"`
	ListIndex uint64      `json:"list_index"`
}

// Target carries both the semantic target kind and a canonical CID string.
type Target struct {
	Kind arcset.TargetKind `json:"kind"`
	CID  string            `json:"cid"`
}

// OptionalTarget encodes absence without JSON null. When State is absent,
// Kind and CID must both be empty.
type OptionalTarget struct {
	State Presence          `json:"state"`
	Kind  arcset.TargetKind `json:"kind"`
	CID   string            `json:"cid"`
}

// OptionalCID encodes an undefined core CID without an empty-string inference.
type OptionalCID struct {
	State Presence `json:"state"`
	CID   string   `json:"cid"`
}

// CommitDescriptor always carries mode and numeric fields. Default commits
// require both numeric fields to be zero; fixed-list commits require a positive
// chunk size and carry the exact total size, including zero for an empty list.
type CommitDescriptor struct {
	Mode      CommitMode `json:"mode"`
	TotalSize uint64     `json:"total_size"`
	ChunkSize uint64     `json:"chunk_size"`
}

// SemanticIntent is the JSON projection of mutation.SemanticIntent.
type SemanticIntent struct {
	Profile     string             `json:"profile"`
	BaseRoot    string             `json:"base_root"`
	Transitions []IntentTransition `json:"transitions"`
	TopOutputID string             `json:"top_output_id"`
}

type IntentTransition struct {
	ID           string              `json:"id"`
	ObjectID     string              `json:"object_id"`
	OldRoot      OptionalCID         `json:"old_root"`
	Kind         arcset.Kind         `json:"kind"`
	Backend      maltcid.BackendKind `json:"backend"`
	Changes      []IntentChange      `json:"changes"`
	Commit       CommitDescriptor    `json:"commit"`
	ExpectedUses uint32              `json:"expected_uses"`
}

type IntentChange struct {
	Coordinate Coordinate     `json:"coordinate"`
	Before     OptionalTarget `json:"before"`
	After      OptionalTarget `json:"after"`
	Output     OptionalOutput `json:"output"`
}

// OptionalOutput makes a child-transition dependency explicit. An absent
// output has empty ID and Kind; a present output is restricted to map/list.
type OptionalOutput struct {
	State Presence          `json:"state"`
	ID    string            `json:"id"`
	Kind  arcset.TargetKind `json:"kind"`
}

type TransitionOutput struct {
	TransitionID string `json:"transition_id"`
	Root         string `json:"root"`
}

// ClientRootBundle binds the complete view and intent to exact local outputs.
// Digests are canonical lowercase, fixed-width SHA-256 hex strings.
type ClientRootBundle struct {
	Profile      string             `json:"profile"`
	OperationID  string             `json:"operation_id"`
	View         UpdateView         `json:"view"`
	Intent       SemanticIntent     `json:"intent"`
	Outputs      []TransitionOutput `json:"outputs"`
	Candidate    string             `json:"candidate"`
	PayloadCIDs  []string           `json:"payload_cids"`
	ViewDigest   string             `json:"view_digest"`
	IntentDigest string             `json:"intent_digest"`
}

type MaterializationReceipt struct {
	Profile         string `json:"profile"`
	OperationID     string `json:"operation_id"`
	BaseRoot        string `json:"base_root"`
	Candidate       string `json:"candidate"`
	BundleDigest    string `json:"bundle_digest"`
	DurableBoundary string `json:"durable_boundary"`
}

// NewUpdateView returns the canonical wire projection of one complete view.
func NewUpdateView(value mutation.UpdateView) (UpdateView, error) {
	canonical, err := mutation.NormalizeUpdateView(value)
	if err != nil {
		return UpdateView{}, err
	}
	objects := make([]UpdateObject, len(canonical.Objects))
	for objectIndex, object := range canonical.Objects {
		entries := object.Entries.Entries()
		wireEntries := make([]ArcEntry, len(entries))
		for entryIndex, entry := range entries {
			coordinate, err := coordinateFromCore(object.Kind, entry.Coordinate)
			if err != nil {
				return UpdateView{}, fmt.Errorf("object %q entry %d: %w", object.ObjectID, entryIndex, err)
			}
			wireEntries[entryIndex] = ArcEntry{
				Coordinate: coordinate,
				Target:     targetFromCore(entry.Target),
			}
		}
		wireCommit := commitFromCore(object.Commit)
		if _, err := wireCommit.core(object.Kind); err != nil {
			return UpdateView{}, fmt.Errorf("object %q commit: %w", object.ObjectID, err)
		}
		objects[objectIndex] = UpdateObject{
			ObjectID: object.ObjectID,
			Root:     object.Root.String(),
			Kind:     object.Kind,
			Entries:  wireEntries,
			Commit:   wireCommit,
		}
	}
	result := UpdateView{
		Profile:      canonical.Profile,
		StateProfile: canonical.StateProfile,
		BaseRoot:     canonical.BaseRoot.String(),
		Bounds: UpdateViewBounds{
			MaxObjects:      canonical.Bounds.MaxObjects,
			MaxTotalEntries: canonical.Bounds.MaxTotalEntries,
			MaxDepth:        canonical.Bounds.MaxDepth,
		},
		Objects: objects,
	}
	if err := validateWireLimits(result); err != nil {
		return UpdateView{}, err
	}
	return result, nil
}

// Core validates and converts a wire update view to its canonical core value.
func (v UpdateView) Core() (mutation.UpdateView, error) {
	if err := validateWireLimits(v); err != nil {
		return mutation.UpdateView{}, err
	}
	baseRoot, err := parseCanonicalCID(v.BaseRoot, "update view base_root")
	if err != nil {
		return mutation.UpdateView{}, err
	}
	objects := make([]mutation.UpdateObject, len(v.Objects))
	for objectIndex, object := range v.Objects {
		root, err := parseCanonicalCID(object.Root, fmt.Sprintf("update object %d root", objectIndex))
		if err != nil {
			return mutation.UpdateView{}, err
		}
		entries := make([]arcset.ArcEntry, len(object.Entries))
		seen := make(map[string]struct{}, len(object.Entries))
		for entryIndex, entry := range object.Entries {
			coordinate, err := entry.Coordinate.core(object.Kind)
			if err != nil {
				return mutation.UpdateView{}, fmt.Errorf("update object %q entry %d: %w", object.ObjectID, entryIndex, err)
			}
			key := string(coordinate.Bytes())
			if _, exists := seen[key]; exists {
				return mutation.UpdateView{}, fmt.Errorf("update object %q has duplicate coordinate %q", object.ObjectID, entry.Coordinate.debugString())
			}
			seen[key] = struct{}{}
			target, err := entry.Target.core()
			if err != nil {
				return mutation.UpdateView{}, fmt.Errorf("update object %q entry %d: %w", object.ObjectID, entryIndex, err)
			}
			entries[entryIndex] = arcset.ArcEntry{Coordinate: coordinate, Target: target}
		}
		canonicalEntries, err := arcset.NewCanonicalArcSet(object.Kind, entries)
		if err != nil {
			return mutation.UpdateView{}, fmt.Errorf("update object %q entries: %w", object.ObjectID, err)
		}
		commit, err := object.Commit.core(object.Kind)
		if err != nil {
			return mutation.UpdateView{}, fmt.Errorf("update object %q commit: %w", object.ObjectID, err)
		}
		objects[objectIndex] = mutation.UpdateObject{
			ObjectID: object.ObjectID,
			Root:     root,
			Kind:     object.Kind,
			Entries:  canonicalEntries,
			Commit:   commit,
		}
	}
	return mutation.NormalizeUpdateView(mutation.UpdateView{
		Profile:      v.Profile,
		StateProfile: v.StateProfile,
		BaseRoot:     baseRoot,
		Bounds: mutation.UpdateViewBounds{
			MaxObjects:      v.Bounds.MaxObjects,
			MaxTotalEntries: v.Bounds.MaxTotalEntries,
			MaxDepth:        v.Bounds.MaxDepth,
		},
		Objects: objects,
	})
}

func (v UpdateView) Validate() error {
	_, err := v.Core()
	return err
}

// NewSemanticIntent returns the canonical child-before-parent wire projection.
func NewSemanticIntent(view mutation.UpdateView, value mutation.SemanticIntent) (SemanticIntent, error) {
	canonical, err := mutation.NormalizeSemanticIntent(view, value)
	if err != nil {
		return SemanticIntent{}, err
	}
	if len(canonical.Transitions) > MaxClientRootTransitions {
		return SemanticIntent{}, fmt.Errorf("semantic intent transition count exceeds %d", MaxClientRootTransitions)
	}
	transitions := make([]IntentTransition, len(canonical.Transitions))
	totalChanges := 0
	for transitionIndex, transition := range canonical.Transitions {
		totalChanges += len(transition.Changes)
		if totalChanges > MaxClientRootChanges {
			return SemanticIntent{}, fmt.Errorf("semantic intent changes exceed %d", MaxClientRootChanges)
		}
		changes := make([]IntentChange, len(transition.Changes))
		for changeIndex, change := range transition.Changes {
			coordinate, err := coordinateFromCore(transition.Kind, change.Coordinate)
			if err != nil {
				return SemanticIntent{}, fmt.Errorf("transition %q change %d: %w", transition.ID, changeIndex, err)
			}
			changes[changeIndex] = IntentChange{
				Coordinate: coordinate,
				Before:     optionalTargetFromCore(change.Before),
				After:      optionalTargetFromCore(change.After),
				Output:     optionalOutputFromCore(change.OutputID, change.OutputKind),
			}
		}
		wireCommit := commitFromCore(transition.Commit)
		if _, err := wireCommit.core(transition.Kind); err != nil {
			return SemanticIntent{}, fmt.Errorf("transition %q commit: %w", transition.ID, err)
		}
		transitions[transitionIndex] = IntentTransition{
			ID:           transition.ID,
			ObjectID:     transition.ObjectID,
			OldRoot:      optionalCIDFromCore(transition.OldRoot),
			Kind:         transition.Kind,
			Backend:      transition.Backend,
			Changes:      changes,
			Commit:       wireCommit,
			ExpectedUses: transition.ExpectedUses,
		}
	}
	return SemanticIntent{
		Profile:     canonical.Profile,
		BaseRoot:    canonical.BaseRoot.String(),
		Transitions: transitions,
		TopOutputID: canonical.TopOutputID,
	}, nil
}

// Core validates and converts a wire intent against its complete update view.
func (i SemanticIntent) Core(view mutation.UpdateView) (mutation.SemanticIntent, error) {
	if len(i.Transitions) == 0 || len(i.Transitions) > MaxClientRootTransitions {
		return mutation.SemanticIntent{}, fmt.Errorf("semantic intent transition count %d is outside 1..%d", len(i.Transitions), MaxClientRootTransitions)
	}
	baseRoot, err := parseCanonicalCID(i.BaseRoot, "semantic intent base_root")
	if err != nil {
		return mutation.SemanticIntent{}, err
	}
	transitions := make([]mutation.IntentTransition, len(i.Transitions))
	totalChanges := 0
	for transitionIndex, transition := range i.Transitions {
		totalChanges += len(transition.Changes)
		if totalChanges > MaxClientRootChanges {
			return mutation.SemanticIntent{}, fmt.Errorf("semantic intent changes exceed %d", MaxClientRootChanges)
		}
		oldRoot, err := transition.OldRoot.core(fmt.Sprintf("transition %q old_root", transition.ID))
		if err != nil {
			return mutation.SemanticIntent{}, err
		}
		commit, err := transition.Commit.core(transition.Kind)
		if err != nil {
			return mutation.SemanticIntent{}, fmt.Errorf("transition %q commit: %w", transition.ID, err)
		}
		changes := make([]mutation.IntentChange, len(transition.Changes))
		for changeIndex, change := range transition.Changes {
			coordinate, err := change.Coordinate.core(transition.Kind)
			if err != nil {
				return mutation.SemanticIntent{}, fmt.Errorf("transition %q change %d: %w", transition.ID, changeIndex, err)
			}
			before, err := change.Before.core(fmt.Sprintf("transition %q change %d before", transition.ID, changeIndex))
			if err != nil {
				return mutation.SemanticIntent{}, err
			}
			after, err := change.After.core(fmt.Sprintf("transition %q change %d after", transition.ID, changeIndex))
			if err != nil {
				return mutation.SemanticIntent{}, err
			}
			outputID, outputKind, err := change.Output.core()
			if err != nil {
				return mutation.SemanticIntent{}, fmt.Errorf("transition %q change %d output: %w", transition.ID, changeIndex, err)
			}
			changes[changeIndex] = mutation.IntentChange{
				Coordinate: coordinate,
				Before:     before,
				After:      after,
				OutputID:   outputID,
				OutputKind: outputKind,
			}
		}
		transitions[transitionIndex] = mutation.IntentTransition{
			ID:           transition.ID,
			ObjectID:     transition.ObjectID,
			OldRoot:      oldRoot,
			Kind:         transition.Kind,
			Backend:      transition.Backend,
			Changes:      changes,
			Commit:       commit,
			ExpectedUses: transition.ExpectedUses,
		}
	}
	return mutation.NormalizeSemanticIntent(view, mutation.SemanticIntent{
		Profile:     i.Profile,
		BaseRoot:    baseRoot,
		Transitions: transitions,
		TopOutputID: i.TopOutputID,
	})
}

func (i SemanticIntent) Validate(view mutation.UpdateView) error {
	_, err := i.Core(view)
	return err
}

// NewClientRootBundle returns the canonical JSON projection of an exact-root
// bundle after all view, dependency, digest, output, and candidate checks.
func NewClientRootBundle(value mutation.ClientRootBundle) (ClientRootBundle, error) {
	canonical, err := mutation.NewClientRootBundle(value)
	if err != nil {
		return ClientRootBundle{}, err
	}
	if len(canonical.Outputs) > MaxClientRootTransitions {
		return ClientRootBundle{}, fmt.Errorf("client-root output count exceeds %d", MaxClientRootTransitions)
	}
	if len(canonical.PayloadCIDs) > MaxClientRootPayloadCIDs {
		return ClientRootBundle{}, fmt.Errorf("client-root payload CID count exceeds %d", MaxClientRootPayloadCIDs)
	}
	view, err := NewUpdateView(canonical.View)
	if err != nil {
		return ClientRootBundle{}, err
	}
	intent, err := NewSemanticIntent(canonical.View, canonical.Intent)
	if err != nil {
		return ClientRootBundle{}, err
	}
	outputs := make([]TransitionOutput, len(canonical.Outputs))
	for index, output := range canonical.Outputs {
		outputs[index] = TransitionOutput{TransitionID: output.TransitionID, Root: output.Root.String()}
	}
	payloads := make([]string, len(canonical.PayloadCIDs))
	for index, payload := range canonical.PayloadCIDs {
		payloads[index] = payload.String()
	}
	return ClientRootBundle{
		Profile:      canonical.Profile,
		OperationID:  canonical.OperationID,
		View:         view,
		Intent:       intent,
		Outputs:      outputs,
		Candidate:    canonical.Candidate.String(),
		PayloadCIDs:  payloads,
		ViewDigest:   hex.EncodeToString(canonical.ViewDigest[:]),
		IntentDigest: hex.EncodeToString(canonical.IntentDigest[:]),
	}, nil
}

// Core validates and converts a wire bundle to its canonical core value.
func (b ClientRootBundle) Core() (mutation.ClientRootBundle, error) {
	if len(b.Outputs) == 0 || len(b.Outputs) > MaxClientRootTransitions {
		return mutation.ClientRootBundle{}, fmt.Errorf("client-root output count %d is outside 1..%d", len(b.Outputs), MaxClientRootTransitions)
	}
	if len(b.PayloadCIDs) > MaxClientRootPayloadCIDs {
		return mutation.ClientRootBundle{}, fmt.Errorf("client-root payload CID count exceeds %d", MaxClientRootPayloadCIDs)
	}
	view, err := b.View.Core()
	if err != nil {
		return mutation.ClientRootBundle{}, err
	}
	intent, err := b.Intent.Core(view)
	if err != nil {
		return mutation.ClientRootBundle{}, err
	}
	outputs := make([]mutation.TransitionOutput, len(b.Outputs))
	for index, output := range b.Outputs {
		root, err := parseCanonicalCID(output.Root, fmt.Sprintf("output %q root", output.TransitionID))
		if err != nil {
			return mutation.ClientRootBundle{}, err
		}
		outputs[index] = mutation.TransitionOutput{TransitionID: output.TransitionID, Root: root}
	}
	candidate, err := parseCanonicalCID(b.Candidate, "client-root candidate")
	if err != nil {
		return mutation.ClientRootBundle{}, err
	}
	payloads := make([]cid.Cid, len(b.PayloadCIDs))
	for index, raw := range b.PayloadCIDs {
		payloads[index], err = parseCanonicalCID(raw, fmt.Sprintf("payload_cids[%d]", index))
		if err != nil {
			return mutation.ClientRootBundle{}, err
		}
	}
	viewDigest, err := parseDigest(b.ViewDigest, "view_digest")
	if err != nil {
		return mutation.ClientRootBundle{}, err
	}
	intentDigest, err := parseDigest(b.IntentDigest, "intent_digest")
	if err != nil {
		return mutation.ClientRootBundle{}, err
	}
	return mutation.NewClientRootBundle(mutation.ClientRootBundle{
		Profile:      b.Profile,
		OperationID:  b.OperationID,
		View:         view,
		Intent:       intent,
		Outputs:      outputs,
		Candidate:    candidate,
		PayloadCIDs:  payloads,
		ViewDigest:   viewDigest,
		IntentDigest: intentDigest,
	})
}

func (b ClientRootBundle) Validate() error {
	_, err := b.Core()
	return err
}

// NewMaterializationReceipt returns a wire receipt only after checking that it
// acknowledges the exact submitted bundle.
func NewMaterializationReceipt(value mutation.MaterializationReceipt, bundle mutation.ClientRootBundle) (MaterializationReceipt, error) {
	if err := value.Validate(bundle); err != nil {
		return MaterializationReceipt{}, err
	}
	return MaterializationReceipt{
		Profile:         value.Profile,
		OperationID:     value.OperationID,
		BaseRoot:        value.BaseRoot.String(),
		Candidate:       value.Candidate.String(),
		BundleDigest:    hex.EncodeToString(value.BundleDigest[:]),
		DurableBoundary: value.DurableBoundary,
	}, nil
}

// Core validates a wire receipt against the exact submitted bundle.
func (r MaterializationReceipt) Core(bundle mutation.ClientRootBundle) (mutation.MaterializationReceipt, error) {
	baseRoot, err := parseCanonicalCID(r.BaseRoot, "materialization receipt base_root")
	if err != nil {
		return mutation.MaterializationReceipt{}, err
	}
	candidate, err := parseCanonicalCID(r.Candidate, "materialization receipt candidate")
	if err != nil {
		return mutation.MaterializationReceipt{}, err
	}
	digest, err := parseDigest(r.BundleDigest, "bundle_digest")
	if err != nil {
		return mutation.MaterializationReceipt{}, err
	}
	value := mutation.MaterializationReceipt{
		Profile:         r.Profile,
		OperationID:     r.OperationID,
		BaseRoot:        baseRoot,
		Candidate:       candidate,
		BundleDigest:    digest,
		DurableBoundary: r.DurableBoundary,
	}
	if err := value.Validate(bundle); err != nil {
		return mutation.MaterializationReceipt{}, err
	}
	return value, nil
}

func (r MaterializationReceipt) Validate(bundle mutation.ClientRootBundle) error {
	_, err := r.Core(bundle)
	return err
}

func validateWireLimits(v UpdateView) error {
	if v.Bounds.MaxObjects == 0 || v.Bounds.MaxObjects > MaxClientRootObjects {
		return fmt.Errorf("update view max_objects must be in 1..%d", MaxClientRootObjects)
	}
	if v.Bounds.MaxTotalEntries == 0 || v.Bounds.MaxTotalEntries > MaxClientRootEntries {
		return fmt.Errorf("update view max_total_entries must be in 1..%d", MaxClientRootEntries)
	}
	if v.Bounds.MaxDepth == 0 || v.Bounds.MaxDepth > MaxClientRootDepth {
		return fmt.Errorf("update view max_depth must be in 1..%d", MaxClientRootDepth)
	}
	if len(v.Objects) == 0 || len(v.Objects) > MaxClientRootObjects || uint64(len(v.Objects)) > uint64(v.Bounds.MaxObjects) {
		return fmt.Errorf("update view object count %d exceeds bounds", len(v.Objects))
	}
	var entries uint64
	for _, object := range v.Objects {
		entries += uint64(len(object.Entries))
		if entries > MaxClientRootEntries || entries > v.Bounds.MaxTotalEntries {
			return fmt.Errorf("update view entry count exceeds bounds")
		}
	}
	return nil
}

func coordinateFromCore(kind arcset.Kind, value arcset.CanonicalCoordinate) (Coordinate, error) {
	raw := value.Bytes()
	switch kind {
	case arcset.KindMap:
		canonical, err := arcset.NewMapCoordinate(string(raw))
		if err != nil || !bytes.Equal(canonical.Bytes(), raw) {
			return Coordinate{}, fmt.Errorf("invalid canonical map coordinate")
		}
		return Coordinate{Kind: kind, MapPath: string(raw)}, nil
	case arcset.KindList:
		if len(raw) != 8 {
			return Coordinate{}, fmt.Errorf("invalid canonical list coordinate")
		}
		return Coordinate{Kind: kind, ListIndex: binary.BigEndian.Uint64(raw)}, nil
	default:
		return Coordinate{}, fmt.Errorf("unsupported coordinate kind %q", kind)
	}
}

func (c Coordinate) core(containingKind arcset.Kind) (arcset.CanonicalCoordinate, error) {
	if c.Kind != containingKind {
		return arcset.CanonicalCoordinate{}, fmt.Errorf("coordinate kind %q does not match containing kind %q", c.Kind, containingKind)
	}
	switch c.Kind {
	case arcset.KindMap:
		if c.MapPath == "" || c.ListIndex != 0 {
			return arcset.CanonicalCoordinate{}, fmt.Errorf("map coordinate must carry only map_path")
		}
		coordinate, err := arcset.NewMapCoordinate(c.MapPath)
		if err != nil {
			return arcset.CanonicalCoordinate{}, err
		}
		if coordinate.String() != c.MapPath {
			return arcset.CanonicalCoordinate{}, fmt.Errorf("map coordinate is not canonical")
		}
		return coordinate, nil
	case arcset.KindList:
		if c.MapPath != "" {
			return arcset.CanonicalCoordinate{}, fmt.Errorf("list coordinate must carry only list_index")
		}
		return arcset.NewListCoordinateUint64(c.ListIndex), nil
	default:
		return arcset.CanonicalCoordinate{}, fmt.Errorf("unsupported coordinate kind %q", c.Kind)
	}
}

func (c Coordinate) debugString() string {
	if c.Kind == arcset.KindList {
		return fmt.Sprintf("%d", c.ListIndex)
	}
	return c.MapPath
}

func targetFromCore(value arcset.TargetRef) Target {
	return Target{Kind: value.Kind(), CID: value.CID().String()}
}

func (t Target) core() (arcset.TargetRef, error) {
	if !knownTargetKind(t.Kind) {
		return arcset.TargetRef{}, fmt.Errorf("unsupported target kind %q", t.Kind)
	}
	target, err := parseCanonicalCID(t.CID, "target CID")
	if err != nil {
		return arcset.TargetRef{}, err
	}
	return arcset.NewTargetRef(t.Kind, target), nil
}

func optionalTargetFromCore(value *arcset.TargetRef) OptionalTarget {
	if value == nil {
		return OptionalTarget{State: PresenceAbsent}
	}
	return OptionalTarget{State: PresencePresent, Kind: value.Kind(), CID: value.CID().String()}
}

func (t OptionalTarget) core(field string) (*arcset.TargetRef, error) {
	switch t.State {
	case PresenceAbsent:
		if t.Kind != "" || t.CID != "" {
			return nil, fmt.Errorf("%s absent target has companion fields", field)
		}
		return nil, nil
	case PresencePresent:
		target, err := (Target{Kind: t.Kind, CID: t.CID}).core()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		return &target, nil
	default:
		return nil, fmt.Errorf("%s has unsupported presence %q", field, t.State)
	}
}

func optionalCIDFromCore(value cid.Cid) OptionalCID {
	if !value.Defined() {
		return OptionalCID{State: PresenceAbsent}
	}
	return OptionalCID{State: PresencePresent, CID: value.String()}
}

func (c OptionalCID) core(field string) (cid.Cid, error) {
	switch c.State {
	case PresenceAbsent:
		if c.CID != "" {
			return cid.Undef, fmt.Errorf("%s absent CID is nonempty", field)
		}
		return cid.Undef, nil
	case PresencePresent:
		return parseCanonicalCID(c.CID, field)
	default:
		return cid.Undef, fmt.Errorf("%s has unsupported presence %q", field, c.State)
	}
}

func optionalOutputFromCore(id string, kind arcset.TargetKind) OptionalOutput {
	if id == "" {
		return OptionalOutput{State: PresenceAbsent}
	}
	return OptionalOutput{State: PresencePresent, ID: id, Kind: kind}
}

func (o OptionalOutput) core() (string, arcset.TargetKind, error) {
	switch o.State {
	case PresenceAbsent:
		if o.ID != "" || o.Kind != "" {
			return "", "", fmt.Errorf("absent output has companion fields")
		}
		return "", "", nil
	case PresencePresent:
		if o.ID == "" || o.Kind != arcset.TargetKindMap && o.Kind != arcset.TargetKindList {
			return "", "", fmt.Errorf("present output must carry id and map/list kind")
		}
		return o.ID, o.Kind, nil
	default:
		return "", "", fmt.Errorf("unsupported output presence %q", o.State)
	}
}

func commitFromCore(value mutation.CommitDescriptor) CommitDescriptor {
	if value.FixedList == nil {
		return CommitDescriptor{Mode: CommitModeDefault}
	}
	return CommitDescriptor{
		Mode:      CommitModeFixedList,
		TotalSize: value.FixedList.TotalSize,
		ChunkSize: value.FixedList.ChunkSize,
	}
}

func (c CommitDescriptor) core(kind arcset.Kind) (mutation.CommitDescriptor, error) {
	switch c.Mode {
	case CommitModeDefault:
		if c.TotalSize != 0 || c.ChunkSize != 0 {
			return mutation.CommitDescriptor{}, fmt.Errorf("default commit has fixed-list fields")
		}
		return mutation.CommitDescriptor{}, nil
	case CommitModeFixedList:
		if kind != arcset.KindList {
			return mutation.CommitDescriptor{}, fmt.Errorf("fixed-list commit requires list kind")
		}
		if c.ChunkSize == 0 {
			return mutation.CommitDescriptor{}, fmt.Errorf("fixed-list chunk_size must be positive")
		}
		return mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{
			TotalSize: c.TotalSize,
			ChunkSize: c.ChunkSize,
		}}, nil
	default:
		return mutation.CommitDescriptor{}, fmt.Errorf("unsupported commit mode %q", c.Mode)
	}
}

func parseCanonicalCID(raw, field string) (cid.Cid, error) {
	if raw == "" || len(raw) > MaxClientRootCIDBytes {
		return cid.Undef, fmt.Errorf("%s length is outside 1..%d", field, MaxClientRootCIDBytes)
	}
	value, err := cid.Decode(raw)
	if err != nil {
		return cid.Undef, fmt.Errorf("invalid %s: %w", field, err)
	}
	if value.String() != raw {
		return cid.Undef, fmt.Errorf("%s is not in canonical CID string form", field)
	}
	return value, nil
}

func parseDigest(raw, field string) ([32]byte, error) {
	if len(raw) != 64 || strings.ToLower(raw) != raw {
		return [32]byte{}, fmt.Errorf("%s must be 64 lowercase hexadecimal characters", field)
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid %s: %w", field, err)
	}
	var value [32]byte
	copy(value[:], decoded)
	return value, nil
}

func knownTargetKind(kind arcset.TargetKind) bool {
	switch kind {
	case arcset.TargetKindUnknown, arcset.TargetKindCAS, arcset.TargetKindMap, arcset.TargetKindList:
		return true
	default:
		return false
	}
}
