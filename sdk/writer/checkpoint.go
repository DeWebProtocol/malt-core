package writer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

const (
	// AuthenticatedCheckpointProfile identifies the in-process writer checkpoint
	// seal. Persistence and protection of the authentication key remain owned by
	// the trusted client; this profile is not a service transition proof.
	AuthenticatedCheckpointProfile = "malt.writer-authenticated-checkpoint/v1"
	checkpointKeyBytes             = 32
)

// AuthenticatedCheckpoint binds one verified update view and its working roots
// to the digest of caller-owned materializer state. The checkpoint can only be
// restored with the same 32-byte client key that created it.
type AuthenticatedCheckpoint struct {
	Profile               string
	View                  mutation.UpdateView
	WorkingRoots          map[string]cid.Cid
	MaterializationDigest [32]byte
	MAC                   [32]byte
}

// Checkpoint seals the currently verified session state to materializationDigest.
// The caller must protect key independently from the cached materializer bytes.
func (s *Session) Checkpoint(materializationDigest [32]byte, key []byte) (AuthenticatedCheckpoint, error) {
	if s == nil {
		return AuthenticatedCheckpoint{}, fmt.Errorf("client writer session is nil")
	}
	if len(key) != checkpointKeyBytes {
		return AuthenticatedCheckpoint{}, fmt.Errorf("client writer checkpoint key must be %d bytes", checkpointKeyBytes)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return AuthenticatedCheckpoint{}, fmt.Errorf("client writer session has no update view")
	}
	view, viewDigest, err := validateVerifiedUpdateView(s.runtime, s.current)
	if err != nil {
		return AuthenticatedCheckpoint{}, err
	}
	if len(s.current.workingRoots) != len(view.Objects) {
		return AuthenticatedCheckpoint{}, fmt.Errorf("verified update view working roots are incomplete")
	}
	roots, err := workingRootsForView(view, s.current.workingRoots)
	if err != nil {
		return AuthenticatedCheckpoint{}, err
	}
	mac, err := checkpointMAC(key, viewDigest, materializationDigest, roots)
	if err != nil {
		return AuthenticatedCheckpoint{}, err
	}
	return AuthenticatedCheckpoint{
		Profile:               AuthenticatedCheckpointProfile,
		View:                  view,
		WorkingRoots:          roots,
		MaterializationDigest: materializationDigest,
		MAC:                   mac,
	}, nil
}

// RestoreCheckpoint installs a previously authenticated local checkpoint
// without recomputing every complete vector. The caller must first restore the
// exact materializer bytes whose digest is bound by checkpoint. A cache miss,
// corrupt materialization, or unavailable key must fall back to Session.Load.
func (s *Session) RestoreCheckpoint(ctx context.Context, checkpoint AuthenticatedCheckpoint, key []byte) error {
	if s == nil {
		return fmt.Errorf("client writer session is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if checkpoint.Profile != AuthenticatedCheckpointProfile {
		return fmt.Errorf("unsupported client writer checkpoint profile %q", checkpoint.Profile)
	}
	if len(key) != checkpointKeyBytes {
		return fmt.Errorf("client writer checkpoint key must be %d bytes", checkpointKeyBytes)
	}
	view, err := mutation.NormalizeUpdateView(checkpoint.View)
	if err != nil {
		return fmt.Errorf("normalize client writer checkpoint view: %w", err)
	}
	if len(checkpoint.WorkingRoots) != len(view.Objects) {
		return fmt.Errorf("client writer checkpoint working roots are incomplete")
	}
	roots, err := workingRootsForView(view, checkpoint.WorkingRoots)
	if err != nil {
		return fmt.Errorf("client writer checkpoint working roots: %w", err)
	}
	viewDigest, err := view.Digest()
	if err != nil {
		return fmt.Errorf("digest client writer checkpoint view: %w", err)
	}
	want, err := checkpointMAC(key, viewDigest, checkpoint.MaterializationDigest, roots)
	if err != nil {
		return err
	}
	if !hmac.Equal(checkpoint.MAC[:], want[:]) {
		return fmt.Errorf("client writer checkpoint authentication failed")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = VerifiedUpdateView{
		View: view, runtime: s.runtime, digest: viewDigest, workingRoots: roots,
	}
	s.loaded = true
	return nil
}

func checkpointMAC(key []byte, viewDigest, materializationDigest [32]byte, roots map[string]cid.Cid) ([32]byte, error) {
	ids := make([]string, 0, len(roots))
	for objectID := range roots {
		ids = append(ids, objectID)
	}
	sort.Strings(ids)

	h := hmac.New(sha256.New, key)
	h.Write([]byte(AuthenticatedCheckpointProfile))
	h.Write([]byte{0})
	h.Write(viewDigest[:])
	h.Write(materializationDigest[:])
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(ids)))
	h.Write(size[:])
	for _, objectID := range ids {
		if uint64(len(objectID)) > uint64(^uint32(0)) {
			return [32]byte{}, fmt.Errorf("client writer checkpoint object id is too large")
		}
		binary.BigEndian.PutUint32(size[:], uint32(len(objectID)))
		h.Write(size[:])
		h.Write([]byte(objectID))
		rootBytes := roots[objectID].Bytes()
		binary.BigEndian.PutUint32(size[:], uint32(len(rootBytes)))
		h.Write(size[:])
		h.Write(rootBytes)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
