package mutation

import (
	"bytes"
	"container/heap"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	UpdateViewProfile              = "malt.update-view/v1"
	SemanticIntentProfile          = "malt.semantic-intent/v1"
	ClientRootBundleProfile        = "malt.client-root-bundle/v1"
	MaterializationReceiptProfile  = "malt.materialization-receipt/v1"
	StatefulCompleteVectorsProfile = "stateful-complete-vectors-v1"
)

var (
	ErrInvalidUpdateView       = errors.New("invalid update view")
	ErrIncompleteUpdateView    = errors.New("incomplete update view")
	ErrUpdateViewCycle         = errors.New("update view cycle")
	ErrInvalidSemanticIntent   = errors.New("invalid semantic intent")
	ErrIntentDependencyCycle   = errors.New("intent dependency cycle")
	ErrIntentMultiplicity      = errors.New("intent output multiplicity mismatch")
	ErrInvalidClientRootBundle = errors.New("invalid client root bundle")
	ErrBundleDigestMismatch    = errors.New("client root bundle digest mismatch")
	ErrBundleCandidateMismatch = errors.New("client root candidate mismatch")
	clientRootIDPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// UpdateViewBounds is part of the authenticated client-writer request. It
// prevents an untrusted service from expanding a small mutation into an
// unbounded state download.
type UpdateViewBounds struct {
	MaxObjects      uint32
	MaxTotalEntries uint64
	MaxDepth        uint32
}

// UpdateView is the complete old semantic closure needed to verify and update
// one accepted root locally. Objects are ordered by ObjectID in canonical
// form. Every typed MALT child reachable from BaseRoot must occur exactly once;
// unrelated objects are rejected.
type UpdateView struct {
	Profile      string
	StateProfile string
	BaseRoot     cid.Cid
	Bounds       UpdateViewBounds
	Objects      []UpdateObject
}

// UpdateObject binds a stable operation-local ID to one complete canonical
// logical vector and its current typed semantic root.
type UpdateObject struct {
	ObjectID string
	Root     cid.Cid
	Kind     arcset.Kind
	Entries  *arcset.CanonicalArcSet
	Commit   CommitDescriptor
}

// SemanticIntent is output-free: child results are referenced by transition
// ID and no candidate root is supplied until local computation finishes.
type SemanticIntent struct {
	Profile     string
	BaseRoot    cid.Cid
	Transitions []IntentTransition
	TopOutputID string
}

// IntentTransition describes one object update. OldRoot may be undefined only
// for a newly-created object. ExpectedUses declares how many parent coordinates
// consume this transition's output; the designated top output has zero uses.
type IntentTransition struct {
	ID           string
	ObjectID     string
	OldRoot      cid.Cid
	Kind         arcset.Kind
	Backend      maltcid.BackendKind
	Changes      []IntentChange
	Commit       CommitDescriptor
	ExpectedUses uint32
}

// IntentChange selects either a literal post-image target or the output of a
// child transition. A nil After and empty OutputID is a deletion. Exactly one
// of After and OutputID may be present.
type IntentChange struct {
	Coordinate arcset.CanonicalCoordinate
	Before     *arcset.TargetRef
	After      *arcset.TargetRef
	OutputID   string
	OutputKind arcset.TargetKind
}

// TransitionOutput binds one normalized transition to the exact root computed
// locally. Outputs are ordered by transition ID in a client-root bundle.
type TransitionOutput struct {
	TransitionID string
	Root         cid.Cid
}

// ClientRootBundle is the exact-root submission. It binds the complete view,
// normalized intent, every intermediate root, referenced payloads, and the
// designated candidate. A Gateway may accept this candidate or reject it; it
// must not substitute a different root.
type ClientRootBundle struct {
	Profile      string
	OperationID  string
	View         UpdateView
	Intent       SemanticIntent
	Outputs      []TransitionOutput
	Candidate    cid.Cid
	PayloadCIDs  []cid.Cid
	ViewDigest   [32]byte
	IntentDigest [32]byte
}

// MaterializationReceipt is a durable acknowledgement of one exact bundle.
// Publication and client trust acceptance remain separate policies.
type MaterializationReceipt struct {
	Profile         string
	OperationID     string
	BaseRoot        cid.Cid
	Candidate       cid.Cid
	BundleDigest    [32]byte
	DurableBoundary string
}

// NormalizeUpdateView validates a view and returns a deep canonical copy.
func NormalizeUpdateView(view UpdateView) (UpdateView, error) {
	if view.Profile != UpdateViewProfile {
		return UpdateView{}, fmt.Errorf("%w: profile must be %q", ErrInvalidUpdateView, UpdateViewProfile)
	}
	if view.StateProfile != StatefulCompleteVectorsProfile {
		return UpdateView{}, fmt.Errorf("%w: state profile must be %q", ErrInvalidUpdateView, StatefulCompleteVectorsProfile)
	}
	if !view.BaseRoot.Defined() {
		return UpdateView{}, fmt.Errorf("%w: base root is undefined", ErrInvalidUpdateView)
	}
	if view.Bounds.MaxObjects == 0 || view.Bounds.MaxTotalEntries == 0 || view.Bounds.MaxDepth == 0 {
		return UpdateView{}, fmt.Errorf("%w: all bounds must be positive", ErrInvalidUpdateView)
	}
	if len(view.Objects) == 0 || uint64(len(view.Objects)) > uint64(view.Bounds.MaxObjects) {
		return UpdateView{}, fmt.Errorf("%w: object count %d exceeds bound %d", ErrInvalidUpdateView, len(view.Objects), view.Bounds.MaxObjects)
	}

	normalized := view
	normalized.Objects = make([]UpdateObject, len(view.Objects))
	byID := make(map[string]struct{}, len(view.Objects))
	byRoot := make(map[string]int, len(view.Objects))
	var totalEntries uint64
	for index, object := range view.Objects {
		if !validClientRootID(object.ObjectID) {
			return UpdateView{}, fmt.Errorf("%w: invalid object id %q", ErrInvalidUpdateView, object.ObjectID)
		}
		if _, exists := byID[object.ObjectID]; exists {
			return UpdateView{}, fmt.Errorf("%w: duplicate object id %q", ErrInvalidUpdateView, object.ObjectID)
		}
		byID[object.ObjectID] = struct{}{}
		if !object.Root.Defined() || !objectKindMatches(object.Root, object.Kind) {
			return UpdateView{}, fmt.Errorf("%w: object %q root/kind mismatch", ErrInvalidUpdateView, object.ObjectID)
		}
		rootKey := object.Root.KeyString()
		if _, exists := byRoot[rootKey]; exists {
			return UpdateView{}, fmt.Errorf("%w: duplicate object root %s", ErrInvalidUpdateView, object.Root)
		}
		if object.Entries == nil || object.Entries.Kind() != object.Kind {
			return UpdateView{}, fmt.Errorf("%w: object %q vector/kind mismatch", ErrInvalidUpdateView, object.ObjectID)
		}
		for _, entry := range object.Entries.Entries() {
			if !clientRootTargetKindMatchesCID(entry.Target) {
				return UpdateView{}, fmt.Errorf("%w: object %q target kind does not match CID semantics at %q", ErrInvalidUpdateView, object.ObjectID, entry.Coordinate.String())
			}
		}
		if object.Commit.FixedList != nil && object.Kind != arcset.KindList {
			return UpdateView{}, fmt.Errorf("%w: object %q has map fixed-list descriptor", ErrInvalidUpdateView, object.ObjectID)
		}
		if err := validateFixedListDescriptor(object.Commit, object.Kind, uint64(object.Entries.Len())); err != nil {
			return UpdateView{}, fmt.Errorf("%w: object %q: %v", ErrInvalidUpdateView, object.ObjectID, err)
		}
		totalEntries += uint64(object.Entries.Len())
		if totalEntries > view.Bounds.MaxTotalEntries {
			return UpdateView{}, fmt.Errorf("%w: total entries exceed bound %d", ErrInvalidUpdateView, view.Bounds.MaxTotalEntries)
		}
		encoded, err := object.Entries.MarshalBinary()
		if err != nil {
			return UpdateView{}, fmt.Errorf("%w: object %q: %v", ErrInvalidUpdateView, object.ObjectID, err)
		}
		entries, err := arcset.UnmarshalCanonicalArcSet(encoded)
		if err != nil {
			return UpdateView{}, fmt.Errorf("%w: object %q: %v", ErrInvalidUpdateView, object.ObjectID, err)
		}
		normalized.Objects[index] = UpdateObject{
			ObjectID: object.ObjectID,
			Root:     object.Root,
			Kind:     object.Kind,
			Entries:  entries,
			Commit:   cloneCommitDescriptor(object.Commit),
		}
		byRoot[rootKey] = index
	}
	slices.SortFunc(normalized.Objects, func(a, b UpdateObject) int {
		return strings.Compare(a.ObjectID, b.ObjectID)
	})
	byRoot = make(map[string]int, len(normalized.Objects))
	for index, object := range normalized.Objects {
		byRoot[object.Root.KeyString()] = index
	}
	baseIndex, exists := byRoot[view.BaseRoot.KeyString()]
	if !exists {
		return UpdateView{}, fmt.Errorf("%w: base root object is missing", ErrIncompleteUpdateView)
	}

	// Build the semantic DAG once. Reachability, cycle detection, and longest
	// root-to-leaf depth are then all checked in O(V+E); recursively revisiting
	// a shared subgraph for every deeper incoming path would make this untrusted
	// download contract vulnerable to CPU amplification.
	children := make([][]int, len(normalized.Objects))
	indegree := make([]uint32, len(normalized.Objects))
	for index, object := range normalized.Objects {
		for _, entry := range object.Entries.Entries() {
			childKind, semantic := semanticTargetKind(entry.Target)
			if !semantic {
				continue
			}
			childIndex, ok := byRoot[entry.Target.CID().KeyString()]
			if !ok {
				return UpdateView{}, fmt.Errorf("%w: object %q references missing %s child %s", ErrIncompleteUpdateView, object.ObjectID, childKind, entry.Target.CID())
			}
			if normalized.Objects[childIndex].Kind != childKind {
				return UpdateView{}, fmt.Errorf("%w: child %s kind mismatch", ErrInvalidUpdateView, entry.Target.CID())
			}
			children[index] = append(children[index], childIndex)
			indegree[childIndex]++
		}
	}

	reachable := make([]bool, len(normalized.Objects))
	stack := []int{baseIndex}
	reachable[baseIndex] = true
	visited := 0
	for len(stack) > 0 {
		index := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visited++
		for _, childIndex := range children[index] {
			if !reachable[childIndex] {
				reachable[childIndex] = true
				stack = append(stack, childIndex)
			}
		}
	}
	if visited != len(normalized.Objects) {
		return UpdateView{}, fmt.Errorf("%w: view contains %d unreachable objects", ErrIncompleteUpdateView, len(normalized.Objects)-visited)
	}

	queue := make([]int, 0, len(normalized.Objects))
	for index, count := range indegree {
		if count == 0 {
			queue = append(queue, index)
		}
	}
	depth := make([]uint32, len(normalized.Objects))
	depth[baseIndex] = 1
	processed := 0
	for head := 0; head < len(queue); head++ {
		index := queue[head]
		processed++
		for _, childIndex := range children[index] {
			candidateDepth := uint64(depth[index]) + 1
			if candidateDepth > uint64(view.Bounds.MaxDepth) {
				return UpdateView{}, fmt.Errorf("%w: depth exceeds bound %d", ErrInvalidUpdateView, view.Bounds.MaxDepth)
			}
			if uint32(candidateDepth) > depth[childIndex] {
				depth[childIndex] = uint32(candidateDepth)
			}
			indegree[childIndex]--
			if indegree[childIndex] == 0 {
				queue = append(queue, childIndex)
			}
		}
	}
	if processed != len(normalized.Objects) {
		return UpdateView{}, ErrUpdateViewCycle
	}
	return normalized, nil
}

// NormalizeSemanticIntent validates an output-free intent against the complete
// update view and returns child-before-parent deterministic order.
func NormalizeSemanticIntent(view UpdateView, intent SemanticIntent) (SemanticIntent, error) {
	normalizedView, err := NormalizeUpdateView(view)
	if err != nil {
		return SemanticIntent{}, err
	}
	if intent.Profile != SemanticIntentProfile {
		return SemanticIntent{}, fmt.Errorf("%w: profile must be %q", ErrInvalidSemanticIntent, SemanticIntentProfile)
	}
	if !intent.BaseRoot.Equals(normalizedView.BaseRoot) {
		return SemanticIntent{}, fmt.Errorf("%w: base root does not match update view", ErrInvalidSemanticIntent)
	}
	if !validClientRootID(intent.TopOutputID) || len(intent.Transitions) == 0 {
		return SemanticIntent{}, fmt.Errorf("%w: invalid top output or empty transition set", ErrInvalidSemanticIntent)
	}

	objects := make(map[string]UpdateObject, len(normalizedView.Objects))
	for _, object := range normalizedView.Objects {
		objects[object.ObjectID] = object
	}
	transitions := make(map[string]IntentTransition, len(intent.Transitions))
	objectTransitions := make(map[string]string, len(intent.Transitions))
	for _, transition := range intent.Transitions {
		if !validClientRootID(transition.ID) || !validClientRootID(transition.ObjectID) {
			return SemanticIntent{}, fmt.Errorf("%w: invalid transition/object id", ErrInvalidSemanticIntent)
		}
		if _, exists := transitions[transition.ID]; exists {
			return SemanticIntent{}, fmt.Errorf("%w: duplicate transition id %q", ErrInvalidSemanticIntent, transition.ID)
		}
		if prior, exists := objectTransitions[transition.ObjectID]; exists {
			return SemanticIntent{}, fmt.Errorf("%w: object %q is updated by both %q and %q; merge changes before normalization", ErrInvalidSemanticIntent, transition.ObjectID, prior, transition.ID)
		}
		objectTransitions[transition.ObjectID] = transition.ID
		object, exists := objects[transition.ObjectID]
		if transition.OldRoot.Defined() {
			if !exists || !transition.OldRoot.Equals(object.Root) || transition.Kind != object.Kind {
				return SemanticIntent{}, fmt.Errorf("%w: transition %q old object does not match update view", ErrInvalidSemanticIntent, transition.ID)
			}
			if transition.Backend != maltcid.BackendKindOf(transition.OldRoot) {
				return SemanticIntent{}, fmt.Errorf("%w: transition %q backend does not match old root", ErrInvalidSemanticIntent, transition.ID)
			}
		} else if exists {
			return SemanticIntent{}, fmt.Errorf("%w: transition %q declares an existing object as new", ErrInvalidSemanticIntent, transition.ID)
		}
		if transition.Backend != maltcid.BackendKindKZG && transition.Backend != maltcid.BackendKindIPA {
			return SemanticIntent{}, fmt.Errorf("%w: transition %q has unsupported backend %q", ErrInvalidSemanticIntent, transition.ID, transition.Backend)
		}
		if transition.Kind != arcset.KindMap && transition.Kind != arcset.KindList {
			return SemanticIntent{}, fmt.Errorf("%w: transition %q has invalid kind %q", ErrInvalidSemanticIntent, transition.ID, transition.Kind)
		}
		if transition.Commit.FixedList != nil && transition.Kind != arcset.KindList {
			return SemanticIntent{}, fmt.Errorf("%w: transition %q has map fixed-list descriptor", ErrInvalidSemanticIntent, transition.ID)
		}
		normalizedTransition, err := normalizeIntentTransition(transition, object)
		if err != nil {
			return SemanticIntent{}, err
		}
		if err := validateTransitionCommit(object, normalizedTransition); err != nil {
			return SemanticIntent{}, fmt.Errorf("%w: transition %q: %v", ErrInvalidSemanticIntent, transition.ID, err)
		}
		transitions[transition.ID] = normalizedTransition
	}
	top, exists := transitions[intent.TopOutputID]
	if !exists || !top.OldRoot.Equals(normalizedView.BaseRoot) || top.ExpectedUses != 0 {
		return SemanticIntent{}, fmt.Errorf("%w: top output must update the base root and have zero uses", ErrInvalidSemanticIntent)
	}

	uses := make(map[string]uint32, len(transitions))
	parents := make(map[string][]string, len(transitions))
	indegree := make(map[string]int, len(transitions))
	for id := range transitions {
		indegree[id] = 0
	}
	for parentID, transition := range transitions {
		for _, change := range transition.Changes {
			if change.OutputID == "" {
				continue
			}
			child, ok := transitions[change.OutputID]
			if !ok {
				return SemanticIntent{}, fmt.Errorf("%w: transition %q references unknown output %q", ErrInvalidSemanticIntent, parentID, change.OutputID)
			}
			if child.Kind == arcset.KindMap && change.OutputKind != arcset.TargetKindMap || child.Kind == arcset.KindList && change.OutputKind != arcset.TargetKindList {
				return SemanticIntent{}, fmt.Errorf("%w: output %q kind mismatch", ErrInvalidSemanticIntent, change.OutputID)
			}
			uses[change.OutputID]++
			parents[change.OutputID] = append(parents[change.OutputID], parentID)
			indegree[parentID]++
		}
	}
	for id, transition := range transitions {
		if uses[id] != transition.ExpectedUses {
			return SemanticIntent{}, fmt.Errorf("%w: output %q declares %d uses, observed %d", ErrIntentMultiplicity, id, transition.ExpectedUses, uses[id])
		}
		if id != intent.TopOutputID && uses[id] == 0 {
			return SemanticIntent{}, fmt.Errorf("%w: output %q is orphaned", ErrInvalidSemanticIntent, id)
		}
	}

	ready := make(stringMinHeap, 0)
	for id, degree := range indegree {
		if degree == 0 {
			ready = append(ready, id)
		}
	}
	heap.Init(&ready)
	ordered := make([]IntentTransition, 0, len(transitions))
	for len(ready) > 0 {
		id := heap.Pop(&ready).(string)
		ordered = append(ordered, transitions[id])
		for _, parentID := range parents[id] {
			indegree[parentID]--
			if indegree[parentID] == 0 {
				heap.Push(&ready, parentID)
			}
		}
	}
	if len(ordered) != len(transitions) {
		return SemanticIntent{}, ErrIntentDependencyCycle
	}
	if ordered[len(ordered)-1].ID != intent.TopOutputID {
		return SemanticIntent{}, fmt.Errorf("%w: dependency graph does not close at top output", ErrInvalidSemanticIntent)
	}
	return SemanticIntent{Profile: intent.Profile, BaseRoot: intent.BaseRoot, Transitions: ordered, TopOutputID: intent.TopOutputID}, nil
}

type stringMinHeap []string

func (values stringMinHeap) Len() int           { return len(values) }
func (values stringMinHeap) Less(i, j int) bool { return values[i] < values[j] }
func (values stringMinHeap) Swap(i, j int)      { values[i], values[j] = values[j], values[i] }

func (values *stringMinHeap) Push(value any) {
	*values = append(*values, value.(string))
}

func (values *stringMinHeap) Pop() any {
	old := *values
	last := len(old) - 1
	value := old[last]
	old[last] = ""
	*values = old[:last]
	return value
}

func normalizeIntentTransition(transition IntentTransition, object UpdateObject) (IntentTransition, error) {
	if len(transition.Changes) == 0 {
		return IntentTransition{}, fmt.Errorf("%w: transition %q has no changes", ErrInvalidSemanticIntent, transition.ID)
	}
	normalized := transition
	normalized.Commit = cloneCommitDescriptor(transition.Commit)
	normalized.Changes = append([]IntentChange(nil), transition.Changes...)
	slices.SortFunc(normalized.Changes, func(a, b IntentChange) int {
		return bytes.Compare(a.Coordinate.Bytes(), b.Coordinate.Bytes())
	})
	var entries map[string]arcset.TargetRef
	if object.Entries != nil {
		entries = make(map[string]arcset.TargetRef, object.Entries.Len())
		for _, entry := range object.Entries.Entries() {
			entries[string(entry.Coordinate.Bytes())] = entry.Target
		}
	}
	for index := range normalized.Changes {
		change := &normalized.Changes[index]
		if len(change.Coordinate.Bytes()) == 0 {
			return IntentTransition{}, fmt.Errorf("%w: transition %q has empty coordinate", ErrInvalidSemanticIntent, transition.ID)
		}
		if index > 0 && bytes.Equal(normalized.Changes[index-1].Coordinate.Bytes(), change.Coordinate.Bytes()) {
			return IntentTransition{}, fmt.Errorf("%w: transition %q has duplicate coordinate %q", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
		}
		if change.After != nil && change.OutputID != "" {
			return IntentTransition{}, fmt.Errorf("%w: transition %q coordinate %q has both literal and output post-image", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
		}
		if change.Before != nil && !clientRootTargetKindMatchesCID(*change.Before) {
			return IntentTransition{}, fmt.Errorf("%w: transition %q before target kind/CID mismatch at %q", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
		}
		if change.After != nil && !clientRootTargetKindMatchesCID(*change.After) {
			return IntentTransition{}, fmt.Errorf("%w: transition %q after target kind/CID mismatch at %q", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
		}
		if change.OutputID != "" {
			if !validClientRootID(change.OutputID) || change.OutputKind != arcset.TargetKindMap && change.OutputKind != arcset.TargetKindList {
				return IntentTransition{}, fmt.Errorf("%w: transition %q has invalid output reference", ErrInvalidSemanticIntent, transition.ID)
			}
		} else if change.OutputKind != "" {
			return IntentTransition{}, fmt.Errorf("%w: transition %q has output kind without output", ErrInvalidSemanticIntent, transition.ID)
		}
		current, present := entries[string(change.Coordinate.Bytes())]
		if change.Before == nil {
			if present {
				return IntentTransition{}, fmt.Errorf("%w: transition %q expected coordinate %q absent", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
			}
		} else if !present || !targetEqual(*change.Before, current) {
			return IntentTransition{}, fmt.Errorf("%w: transition %q before-image mismatch at %q", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
		}
		if change.After == nil && change.OutputID == "" && change.Before == nil {
			return IntentTransition{}, fmt.Errorf("%w: transition %q has empty change at %q", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
		}
		if change.After != nil && change.Before != nil && targetEqual(*change.After, *change.Before) {
			return IntentTransition{}, fmt.Errorf("%w: transition %q has no-op at %q", ErrInvalidSemanticIntent, transition.ID, change.Coordinate.String())
		}
	}
	return normalized, nil
}

func validateTransitionCommit(object UpdateObject, transition IntentTransition) error {
	if transition.Kind != arcset.KindList {
		if transition.Commit.FixedList != nil {
			return errors.New("map transition has a fixed-list descriptor")
		}
		return nil
	}
	postCount, err := postTransitionListCount(object, transition)
	if err != nil {
		return err
	}
	if err := validateFixedListDescriptor(transition.Commit, transition.Kind, postCount); err != nil {
		return err
	}
	if !transition.OldRoot.Defined() {
		return nil
	}
	oldFixed, newFixed := object.Commit.FixedList, transition.Commit.FixedList
	if (oldFixed == nil) != (newFixed == nil) {
		return errors.New("list transition changes its plain/fixed representation")
	}
	if oldFixed == nil {
		return nil
	}
	if oldFixed.ChunkSize != newFixed.ChunkSize {
		return errors.New("fixed-list transition changes chunk size")
	}
	oldCount := uint64(object.Entries.Len())
	switch {
	case postCount < oldCount:
		return errors.New("fixed-list truncate is unsupported")
	case postCount == oldCount && oldFixed.TotalSize != newFixed.TotalSize:
		return errors.New("fixed-list replacement changes total size")
	case postCount > oldCount && oldFixed.TotalSize%oldFixed.ChunkSize != 0:
		return errors.New("fixed-list append requires a chunk-aligned old total size")
	case postCount > oldCount && newFixed.TotalSize <= oldFixed.TotalSize:
		return errors.New("fixed-list append does not increase total size")
	}
	return nil
}

func postTransitionListCount(object UpdateObject, transition IntentTransition) (uint64, error) {
	oldEntries := 0
	if object.Entries != nil {
		oldEntries = object.Entries.Len()
	}
	present := make(map[uint64]struct{}, oldEntries+len(transition.Changes))
	if object.Entries != nil {
		for _, entry := range object.Entries.Entries() {
			raw := entry.Coordinate.Bytes()
			if len(raw) != 8 {
				return 0, errors.New("list object contains a non-index coordinate")
			}
			present[binary.BigEndian.Uint64(raw)] = struct{}{}
		}
	}
	for _, change := range transition.Changes {
		raw := change.Coordinate.Bytes()
		if len(raw) != 8 {
			return 0, errors.New("list transition contains a non-index coordinate")
		}
		index := binary.BigEndian.Uint64(raw)
		if change.After == nil && change.OutputID == "" {
			delete(present, index)
		} else {
			present[index] = struct{}{}
		}
	}
	count := uint64(len(present))
	for index := uint64(0); index < count; index++ {
		if _, ok := present[index]; !ok {
			return 0, errors.New("list transition creates a sparse post-image")
		}
	}
	return count, nil
}

func validateFixedListDescriptor(descriptor CommitDescriptor, kind arcset.Kind, count uint64) error {
	if descriptor.FixedList == nil {
		return nil
	}
	if kind != arcset.KindList {
		return errors.New("fixed-list descriptor belongs to a non-list object")
	}
	fixed := descriptor.FixedList
	if fixed.ChunkSize == 0 {
		return errors.New("fixed-list chunk size is zero")
	}
	wantCount := fixed.TotalSize / fixed.ChunkSize
	if fixed.TotalSize%fixed.ChunkSize != 0 {
		wantCount++
	}
	if wantCount != count {
		return fmt.Errorf("fixed-list descriptor implies %d chunks, vector has %d", wantCount, count)
	}
	return nil
}

// NewClientRootBundle validates and canonicalizes one exact-root submission.
func NewClientRootBundle(bundle ClientRootBundle) (ClientRootBundle, error) {
	if bundle.Profile != ClientRootBundleProfile || !validClientRootID(bundle.OperationID) {
		return ClientRootBundle{}, fmt.Errorf("%w: invalid profile or operation id", ErrInvalidClientRootBundle)
	}
	view, err := NormalizeUpdateView(bundle.View)
	if err != nil {
		return ClientRootBundle{}, err
	}
	intent, err := NormalizeSemanticIntent(view, bundle.Intent)
	if err != nil {
		return ClientRootBundle{}, err
	}
	viewDigest, err := view.Digest()
	if err != nil {
		return ClientRootBundle{}, err
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return ClientRootBundle{}, err
	}
	if bundle.ViewDigest != viewDigest || bundle.IntentDigest != intentDigest {
		return ClientRootBundle{}, ErrBundleDigestMismatch
	}

	outputs := append([]TransitionOutput(nil), bundle.Outputs...)
	slices.SortFunc(outputs, func(a, b TransitionOutput) int { return strings.Compare(a.TransitionID, b.TransitionID) })
	if len(outputs) != len(intent.Transitions) {
		return ClientRootBundle{}, fmt.Errorf("%w: output count mismatch", ErrInvalidClientRootBundle)
	}
	transitionIDs := make(map[string]struct{}, len(intent.Transitions))
	transitionByID := make(map[string]IntentTransition, len(intent.Transitions))
	for _, transition := range intent.Transitions {
		transitionIDs[transition.ID] = struct{}{}
		transitionByID[transition.ID] = transition
	}
	var topRoot cid.Cid
	for index, output := range outputs {
		if !output.Root.Defined() {
			return ClientRootBundle{}, fmt.Errorf("%w: output %q root is undefined", ErrInvalidClientRootBundle, output.TransitionID)
		}
		if index > 0 && outputs[index-1].TransitionID == output.TransitionID {
			return ClientRootBundle{}, fmt.Errorf("%w: duplicate output %q", ErrInvalidClientRootBundle, output.TransitionID)
		}
		if _, exists := transitionIDs[output.TransitionID]; !exists {
			return ClientRootBundle{}, fmt.Errorf("%w: unknown output %q", ErrInvalidClientRootBundle, output.TransitionID)
		}
		transition := transitionByID[output.TransitionID]
		if !maltcid.IsMaltCid(output.Root) || maltcid.BackendKindOf(output.Root) != transition.Backend ||
			transition.Kind == arcset.KindMap && maltcid.SemanticKindOf(output.Root) != maltcid.SemanticKindMap ||
			transition.Kind == arcset.KindList && maltcid.SemanticKindOf(output.Root) != maltcid.SemanticKindList {
			return ClientRootBundle{}, fmt.Errorf("%w: output %q root kind/backend mismatch", ErrInvalidClientRootBundle, output.TransitionID)
		}
		if output.TransitionID == intent.TopOutputID {
			topRoot = output.Root
		}
	}
	if !bundle.Candidate.Defined() || !bundle.Candidate.Equals(topRoot) {
		return ClientRootBundle{}, ErrBundleCandidateMismatch
	}
	payloads := append([]cid.Cid(nil), bundle.PayloadCIDs...)
	slices.SortFunc(payloads, compareCID)
	for index, payload := range payloads {
		if !payload.Defined() {
			return ClientRootBundle{}, fmt.Errorf("%w: undefined payload CID", ErrInvalidClientRootBundle)
		}
		if index > 0 && payload.Equals(payloads[index-1]) {
			return ClientRootBundle{}, fmt.Errorf("%w: duplicate payload CID %s", ErrInvalidClientRootBundle, payload)
		}
	}
	wantPayloads := literalPayloadCIDs(intent)
	if len(payloads) != len(wantPayloads) {
		return ClientRootBundle{}, fmt.Errorf("%w: payload CID set does not match literal CAS post-images", ErrInvalidClientRootBundle)
	}
	for index := range payloads {
		if !payloads[index].Equals(wantPayloads[index]) {
			return ClientRootBundle{}, fmt.Errorf("%w: payload CID set does not match literal CAS post-images", ErrInvalidClientRootBundle)
		}
	}
	bundle.View = view
	bundle.Intent = intent
	bundle.Outputs = outputs
	bundle.PayloadCIDs = payloads
	return bundle, nil
}

func literalPayloadCIDs(intent SemanticIntent) []cid.Cid {
	byKey := make(map[string]cid.Cid)
	for _, transition := range intent.Transitions {
		for _, change := range transition.Changes {
			if change.After == nil {
				continue
			}
			if _, semantic := semanticTargetKind(*change.After); semantic {
				continue
			}
			byKey[change.After.CID().KeyString()] = change.After.CID()
		}
	}
	values := make([]cid.Cid, 0, len(byKey))
	for _, value := range byKey {
		values = append(values, value)
	}
	slices.SortFunc(values, compareCID)
	return values
}

// Validate checks a durable receipt against the exact submitted bundle.
func (r MaterializationReceipt) Validate(bundle ClientRootBundle) error {
	canonical, err := NewClientRootBundle(bundle)
	if err != nil {
		return err
	}
	if r.Profile != MaterializationReceiptProfile || r.OperationID != canonical.OperationID || strings.TrimSpace(r.DurableBoundary) == "" {
		return fmt.Errorf("invalid materialization receipt metadata")
	}
	if !r.BaseRoot.Equals(canonical.View.BaseRoot) || !r.Candidate.Equals(canonical.Candidate) {
		return fmt.Errorf("materialization receipt root mismatch")
	}
	digest, err := canonical.Digest()
	if err != nil {
		return err
	}
	if r.BundleDigest != digest {
		return fmt.Errorf("materialization receipt bundle digest mismatch")
	}
	return nil
}

// Digest returns the deterministic SHA-256 digest of a canonical update view.
func (v UpdateView) Digest() ([32]byte, error) {
	canonical, err := NormalizeUpdateView(v)
	if err != nil {
		return [32]byte{}, err
	}
	var encoded bytes.Buffer
	writeDigestString(&encoded, canonical.Profile)
	writeDigestString(&encoded, canonical.StateProfile)
	writeDigestCID(&encoded, canonical.BaseRoot)
	writeDigestUint32(&encoded, canonical.Bounds.MaxObjects)
	writeDigestUint64(&encoded, canonical.Bounds.MaxTotalEntries)
	writeDigestUint32(&encoded, canonical.Bounds.MaxDepth)
	writeDigestUint32(&encoded, uint32(len(canonical.Objects)))
	for _, object := range canonical.Objects {
		writeDigestString(&encoded, object.ObjectID)
		writeDigestCID(&encoded, object.Root)
		writeDigestString(&encoded, string(object.Kind))
		vector, err := object.Entries.MarshalBinary()
		if err != nil {
			return [32]byte{}, err
		}
		writeDigestBytes(&encoded, vector)
		writeCommitDescriptor(&encoded, object.Commit)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

// Digest returns the deterministic SHA-256 digest of a normalized intent.
func (i SemanticIntent) Digest() ([32]byte, error) {
	// A digest caller must bind a view separately; ordering and local shape are
	// still checked here without pretending to revalidate before-images.
	if i.Profile != SemanticIntentProfile || !i.BaseRoot.Defined() || len(i.Transitions) == 0 || !validClientRootID(i.TopOutputID) {
		return [32]byte{}, ErrInvalidSemanticIntent
	}
	var encoded bytes.Buffer
	writeDigestString(&encoded, i.Profile)
	writeDigestCID(&encoded, i.BaseRoot)
	writeDigestString(&encoded, i.TopOutputID)
	writeDigestUint32(&encoded, uint32(len(i.Transitions)))
	for _, transition := range i.Transitions {
		writeDigestString(&encoded, transition.ID)
		writeDigestString(&encoded, transition.ObjectID)
		writeDigestCID(&encoded, transition.OldRoot)
		writeDigestString(&encoded, string(transition.Kind))
		writeDigestString(&encoded, string(transition.Backend))
		writeCommitDescriptor(&encoded, transition.Commit)
		writeDigestUint32(&encoded, transition.ExpectedUses)
		writeDigestUint32(&encoded, uint32(len(transition.Changes)))
		for _, change := range transition.Changes {
			writeDigestBytes(&encoded, change.Coordinate.Bytes())
			writeTarget(&encoded, change.Before)
			writeTarget(&encoded, change.After)
			writeDigestString(&encoded, change.OutputID)
			writeDigestString(&encoded, string(change.OutputKind))
		}
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

// Digest returns the deterministic SHA-256 digest of a canonical bundle.
func (b ClientRootBundle) Digest() ([32]byte, error) {
	canonical, err := NewClientRootBundle(b)
	if err != nil {
		return [32]byte{}, err
	}
	var encoded bytes.Buffer
	writeDigestString(&encoded, canonical.Profile)
	writeDigestString(&encoded, canonical.OperationID)
	writeDigestBytes(&encoded, canonical.ViewDigest[:])
	writeDigestBytes(&encoded, canonical.IntentDigest[:])
	writeDigestCID(&encoded, canonical.Candidate)
	writeDigestUint32(&encoded, uint32(len(canonical.Outputs)))
	for _, output := range canonical.Outputs {
		writeDigestString(&encoded, output.TransitionID)
		writeDigestCID(&encoded, output.Root)
	}
	writeDigestUint32(&encoded, uint32(len(canonical.PayloadCIDs)))
	for _, payload := range canonical.PayloadCIDs {
		writeDigestCID(&encoded, payload)
	}
	return sha256.Sum256(encoded.Bytes()), nil
}

func semanticTargetKind(target arcset.TargetRef) (arcset.Kind, bool) {
	switch target.Kind() {
	case arcset.TargetKindMap:
		return arcset.KindMap, true
	case arcset.TargetKindList:
		return arcset.KindList, true
	case arcset.TargetKindCAS:
		return "", false
	}
	switch maltcid.SemanticKindOf(target.CID()) {
	case maltcid.SemanticKindMap:
		return arcset.KindMap, true
	case maltcid.SemanticKindList:
		return arcset.KindList, true
	default:
		return "", false
	}
}

// clientRootTargetKindMatchesCID prevents an untrusted update view from
// relabeling a typed semantic child as opaque CAS data (and thereby escaping
// closure validation), or from relabeling an ordinary payload as a semantic
// child. Unknown/CAS remain valid spellings only for non-MALT payload CIDs.
func clientRootTargetKindMatchesCID(target arcset.TargetRef) bool {
	semantic := maltcid.SemanticKindOf(target.CID())
	switch target.Kind() {
	case arcset.TargetKindMap:
		return semantic == maltcid.SemanticKindMap
	case arcset.TargetKindList:
		return semantic == maltcid.SemanticKindList
	case arcset.TargetKindCAS, arcset.TargetKindUnknown:
		return semantic == maltcid.SemanticKindUnknown
	default:
		return false
	}
}

func cloneCommitDescriptor(value CommitDescriptor) CommitDescriptor {
	if value.FixedList == nil {
		return CommitDescriptor{}
	}
	fixed := *value.FixedList
	return CommitDescriptor{FixedList: &fixed}
}

func targetEqual(a, b arcset.TargetRef) bool {
	return a.Kind() == b.Kind() && a.CID().Equals(b.CID())
}

func compareCID(a, b cid.Cid) int {
	return bytes.Compare(a.Bytes(), b.Bytes())
}

func validClientRootID(value string) bool {
	return clientRootIDPattern.MatchString(value)
}

func writeDigestString(buf *bytes.Buffer, value string) {
	writeDigestBytes(buf, []byte(value))
}

func writeDigestBytes(buf *bytes.Buffer, value []byte) {
	writeDigestUint64(buf, uint64(len(value)))
	buf.Write(value)
}

func writeDigestCID(buf *bytes.Buffer, value cid.Cid) {
	writeDigestBytes(buf, value.Bytes())
}

func writeDigestUint32(buf *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	buf.Write(raw[:])
}

func writeDigestUint64(buf *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	buf.Write(raw[:])
}

func writeCommitDescriptor(buf *bytes.Buffer, value CommitDescriptor) {
	if value.FixedList == nil {
		buf.WriteByte(0)
		return
	}
	buf.WriteByte(1)
	writeDigestUint64(buf, value.FixedList.TotalSize)
	writeDigestUint64(buf, value.FixedList.ChunkSize)
}

func writeTarget(buf *bytes.Buffer, value *arcset.TargetRef) {
	if value == nil {
		buf.WriteByte(0)
		return
	}
	buf.WriteByte(1)
	writeDigestString(buf, string(value.Kind()))
	writeDigestCID(buf, value.CID())
}
