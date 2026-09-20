package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	materializermemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/protocol"
	clientwriter "github.com/dewebprotocol/malt-core/sdk/writer"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	writerSnapshotProfile = "malt.ts.writer-session-snapshot/v1"
	// SnapshotKeyBytes is the checkpoint authentication key length.
	SnapshotKeyBytes = 32
	// MaxSnapshotBytes bounds serialized complete session snapshots.
	MaxSnapshotBytes = 64 << 20
)

type writerSessionSnapshot struct {
	Profile               string            `json:"profile"`
	Backend               string            `json:"backend"`
	BaseRoot              string            `json:"base_root"`
	View                  json.RawMessage   `json:"view"`
	WorkingRoots          map[string]string `json:"working_roots"`
	Materialization       json.RawMessage   `json:"materialization"`
	MaterializationDigest string            `json:"materialization_sha256"`
	MAC                   []byte            `json:"checkpoint_mac"`
}

func (s *Session) Snapshot(key []byte) ([]byte, error) {
	if s == nil || s.computer == nil {
		return nil, fmt.Errorf("client writer session is not initialized")
	}
	if len(key) != SnapshotKeyBytes {
		return nil, fmt.Errorf("client writer snapshot key must be %d bytes", SnapshotKeyBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.session == nil || s.store == nil {
		return nil, fmt.Errorf("client writer session has no update view")
	}
	if len(s.prepared) != 0 {
		return nil, fmt.Errorf("client writer session cannot snapshot prepared candidates")
	}

	materializationState, err := s.store.ExportState()
	if err != nil {
		return nil, fmt.Errorf("export client writer materialization: %w", err)
	}
	materializationJSON, err := json.Marshal(materializationState)
	if err != nil {
		return nil, fmt.Errorf("encode client writer materialization: %w", err)
	}
	materializationDigest := sha256.Sum256(materializationJSON)
	checkpoint, err := s.session.Checkpoint(materializationDigest, key)
	if err != nil {
		return nil, fmt.Errorf("seal client writer checkpoint: %w", err)
	}
	wireView, err := protocol.NewUpdateView(checkpoint.View)
	if err != nil {
		return nil, fmt.Errorf("encode client writer checkpoint view: %w", err)
	}
	viewJSON, err := json.Marshal(wireView)
	if err != nil {
		return nil, fmt.Errorf("encode client writer checkpoint view: %w", err)
	}
	roots := make(map[string]string, len(checkpoint.WorkingRoots))
	for objectID, root := range checkpoint.WorkingRoots {
		roots[objectID] = root.String()
	}
	encoded, err := json.Marshal(writerSessionSnapshot{
		Profile:               writerSnapshotProfile,
		Backend:               string(maltcid.BackendKindOf(checkpoint.View.BaseRoot)),
		BaseRoot:              checkpoint.View.BaseRoot.String(),
		View:                  viewJSON,
		WorkingRoots:          roots,
		Materialization:       materializationJSON,
		MaterializationDigest: hex.EncodeToString(materializationDigest[:]),
		MAC:                   append([]byte(nil), checkpoint.MAC[:]...),
	})
	if err != nil {
		return nil, fmt.Errorf("encode client writer snapshot: %w", err)
	}
	if len(encoded) > MaxSnapshotBytes {
		return nil, fmt.Errorf("client writer snapshot exceeds %d bytes", MaxSnapshotBytes)
	}
	return encoded, nil
}

func (s *Session) Restore(ctx context.Context, snapshotJSON, key []byte) ([]byte, error) {
	if s == nil || s.computer == nil {
		return nil, fmt.Errorf("client writer session is not initialized")
	}
	if len(key) != SnapshotKeyBytes {
		return nil, fmt.Errorf("client writer snapshot key must be %d bytes", SnapshotKeyBytes)
	}
	if len(snapshotJSON) == 0 || len(snapshotJSON) > MaxSnapshotBytes {
		return nil, fmt.Errorf("client writer snapshot must contain at most %d bytes", MaxSnapshotBytes)
	}

	var snapshot writerSessionSnapshot
	if err := decodeStrictJSON(snapshotJSON, &snapshot); err != nil {
		return nil, fmt.Errorf("decode client writer snapshot: %w", err)
	}
	if snapshot.Profile != writerSnapshotProfile {
		return nil, fmt.Errorf("unsupported client writer snapshot profile %q", snapshot.Profile)
	}
	if len(snapshot.MAC) != sha256.Size {
		return nil, fmt.Errorf("client writer snapshot has an invalid checkpoint MAC")
	}
	wireView, err := protocol.DecodeUpdateView(snapshot.View)
	if err != nil {
		return nil, fmt.Errorf("decode client writer snapshot view: %w", err)
	}
	view, err := wireView.Core()
	if err != nil {
		return nil, fmt.Errorf("decode client writer snapshot view: %w", err)
	}
	if snapshot.BaseRoot != view.BaseRoot.String() {
		return nil, fmt.Errorf("client writer snapshot base root differs from its view")
	}
	backend := maltcid.BackendKindOf(view.BaseRoot)
	if snapshot.Backend != string(backend) {
		return nil, fmt.Errorf("client writer snapshot backend differs from its view")
	}
	if _, available := s.computer.schemes[backend]; !available || len(s.computer.schemes) != 1 {
		return nil, fmt.Errorf("client writer snapshot backend %q is not loaded", backend)
	}

	digest := sha256.Sum256(snapshot.Materialization)
	declaredDigest, err := hex.DecodeString(snapshot.MaterializationDigest)
	if err != nil || len(declaredDigest) != sha256.Size || !bytes.Equal(declaredDigest, digest[:]) {
		return nil, fmt.Errorf("client writer snapshot materialization digest mismatch")
	}
	var state materializermemory.State
	if err := decodeStrictJSON(snapshot.Materialization, &state); err != nil {
		return nil, fmt.Errorf("decode client writer materialization: %w", err)
	}
	store, err := materializermemory.NewFromState(state)
	if err != nil {
		return nil, fmt.Errorf("restore client writer materialization: %w", err)
	}
	runtime, store, err := s.computer.newSessionRuntimeWithStore(store)
	if err != nil {
		return nil, err
	}
	session, err := clientwriter.NewSession(runtime)
	if err != nil {
		return nil, err
	}
	roots := make(map[string]cid.Cid, len(snapshot.WorkingRoots))
	for objectID, encodedRoot := range snapshot.WorkingRoots {
		root, err := cid.Decode(encodedRoot)
		if err != nil {
			return nil, fmt.Errorf("decode client writer snapshot root for %q: %w", objectID, err)
		}
		roots[objectID] = root
	}
	var mac [sha256.Size]byte
	copy(mac[:], snapshot.MAC)
	if err := session.RestoreCheckpoint(ctx, clientwriter.AuthenticatedCheckpoint{
		Profile:               clientwriter.AuthenticatedCheckpointProfile,
		View:                  view,
		WorkingRoots:          roots,
		MaterializationDigest: digest,
		MAC:                   mac,
	}, key); err != nil {
		return nil, fmt.Errorf("authenticate client writer snapshot: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store != nil {
		s.store.RetainRoots(nil)
	}
	s.session = session
	s.store = store
	s.view = view
	s.bootstrapBase = nil
	s.prepared = make(map[string]preparedCandidate)
	s.preparedResponseBytes = 0
	normalizedView, err := protocol.NewUpdateView(view)
	if err != nil {
		return nil, fmt.Errorf("encode restored client writer view: %w", err)
	}
	return json.Marshal(normalizedView)
}

func decodeStrictJSON(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}
