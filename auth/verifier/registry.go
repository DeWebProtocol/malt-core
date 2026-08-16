package verifier

import (
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type backendVerifiers struct {
	maps  MapVerifier
	lists ListVerifier
}

// BackendRegistry maps the backend kind encoded in a typed MALT CID to pure
// map/list verification implementations.
type BackendRegistry struct {
	backends map[maltcid.BackendKind]backendVerifiers
}

// NewBackendRegistry creates an empty backend registry.
func NewBackendRegistry() *BackendRegistry {
	return &BackendRegistry{backends: make(map[maltcid.BackendKind]backendVerifiers)}
}

// Register installs verification-only map and list implementations for kind.
func (r *BackendRegistry) Register(kind maltcid.BackendKind, maps MapVerifier, lists ListVerifier) error {
	if r == nil {
		return fmt.Errorf("backend registry is nil")
	}
	if kind == maltcid.BackendKindUnknown {
		return fmt.Errorf("commitment backend kind is unknown")
	}
	if maps == nil {
		return fmt.Errorf("map verifier for backend %q is nil", kind)
	}
	if lists == nil {
		return fmt.Errorf("list verifier for backend %q is nil", kind)
	}
	if r.backends == nil {
		r.backends = make(map[maltcid.BackendKind]backendVerifiers)
	}
	r.backends[kind] = backendVerifiers{maps: maps, lists: lists}
	return nil
}

// RegisterScheme installs the built-in radix-map and tree-list proof decoders
// over one primitive commitment scheme.
func (r *BackendRegistry) RegisterScheme(kind maltcid.BackendKind, scheme commitment.IndexVerifier) error {
	if scheme == nil {
		return fmt.Errorf("commitment scheme for backend %q is nil", kind)
	}
	geometry, err := nodegeometry.ForBackend(kind)
	if err != nil {
		return fmt.Errorf("commitment backend %q geometry: %w", kind, err)
	}
	if scheme.MaxValues() != geometry.NodeWidth() {
		return fmt.Errorf(
			"commitment backend %q capacity %d does not match required node width %d",
			kind, scheme.MaxValues(), geometry.NodeWidth(),
		)
	}
	return r.Register(kind, newRadixMapVerifier(scheme, geometry), newTreeListVerifier(scheme, geometry))
}

func (r *BackendRegistry) mapVerifier(root cid.Cid) (MapVerifier, error) {
	if maltcid.SemanticKindOf(root) != maltcid.SemanticKindMap {
		return nil, fmt.Errorf("map evidence starts from non-map root %s", root)
	}
	entry, err := r.lookup(root)
	if err != nil {
		return nil, err
	}
	return entry.maps, nil
}

func (r *BackendRegistry) listVerifier(root cid.Cid) (ListVerifier, error) {
	if maltcid.SemanticKindOf(root) != maltcid.SemanticKindList {
		return nil, fmt.Errorf("list evidence starts from non-list root %s", root)
	}
	entry, err := r.lookup(root)
	if err != nil {
		return nil, err
	}
	return entry.lists, nil
}

func (r *BackendRegistry) lookup(root cid.Cid) (backendVerifiers, error) {
	if r == nil {
		return backendVerifiers{}, fmt.Errorf("backend registry is nil")
	}
	kind := maltcid.BackendKindOf(root)
	if kind == maltcid.BackendKindUnknown {
		return backendVerifiers{}, fmt.Errorf("root %s does not encode a supported MALT commitment backend", root)
	}
	entry, ok := r.backends[kind]
	if !ok {
		return backendVerifiers{}, fmt.Errorf("commitment backend %q is not registered", kind)
	}
	return entry, nil
}

// NewDefaultBackendRegistry creates the portable built-in KZG/IPA registry.
func NewDefaultBackendRegistry() (*BackendRegistry, error) {
	registry := NewBackendRegistry()

	kzgScheme, err := kzg.NewVerifierScheme()
	if err != nil {
		return nil, fmt.Errorf("creating KZG verifier backend: %w", err)
	}
	if err := registry.RegisterScheme(maltcid.BackendKindKZG, kzgScheme); err != nil {
		return nil, err
	}

	ipaScheme, err := ipa.NewVerifierScheme()
	if err != nil {
		return nil, fmt.Errorf("creating IPA verifier backend: %w", err)
	}
	if err := registry.RegisterScheme(maltcid.BackendKindIPA, ipaScheme); err != nil {
		return nil, err
	}
	return registry, nil
}
