package generate

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

// GenerateAuthentication emits current authentication query vectors over V=0
// Roots. Earlier corpus revisions remain immutable in Git history.
func GenerateAuthentication() ([]byte, error) {
	type vector struct {
		ID           string                              `json:"id"`
		Verification protocol.AuthenticationVerification `json:"verification"`
		Valid        bool                                `json:"valid"`
	}
	corpus := struct {
		Schema  string   `json:"schema"`
		Vectors []vector `json:"vectors"`
	}{Schema: "malt.conformance.authentication/3", Vectors: []vector{}}
	ctx := context.Background()
	for _, profile := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		var scheme engine.Profile
		var err error
		if profile == maltcid.KZG4096 {
			scheme, err = kzg.NewScheme()
		} else {
			scheme, err = ipa.NewCommitterScheme(ipa.ProfileDirect)
		}
		if err != nil {
			return nil, err
		}
		profiles := engine.NewRegistry()
		if err := profiles.Register(scheme); err != nil {
			return nil, err
		}
		e := engine.New(profiles)
		nodes := memory.NewNodes()
		state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, DerivationProfile: uint8(derivation.SHA256), Profile: profile}, Entries: []engine.Entry{{Label: []byte("a/b"), Target: cid.MustParse("bafkqaaa")}, {Label: []byte("@payload"), Target: cid.MustParse("bafkqaaa")}, {Label: []byte{}, Target: cid.MustParse("bafkqaaa")}}}
		root, err := e.Build(ctx, state, nodes)
		if err != nil {
			return nil, err
		}
		add := func(name string, q protocol.AuthenticationRequest) error {
			result, err := authentication.Execute(ctx, e, q, nodes)
			if err != nil {
				return err
			}
			encoded, err := json.Marshal(protocol.AuthenticationVerification{Request: q, Result: result})
			if err != nil {
				return err
			}
			value, err := protocol.DecodeAuthenticationVerification(encoded)
			if err != nil {
				return err
			}
			corpus.Vectors = append(corpus.Vectors, vector{fmt.Sprintf("profile-%d.%s", profile, name), value, true})
			return nil
		}
		bindingStart := len(corpus.Vectors)
		for _, query := range []struct {
			name  string
			value []byte
		}{{"opaque-label", []byte("a/b")}, {"system-payload", []byte("@payload")}, {"literal-at-payload-absent", []byte("@payload")}, {"missing", []byte("absent")}, {"empty-label", []byte{}}} {
			value := query.value
			q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: root.String(), Steps: [][]byte{}, Operation: "binding", Label: &value}
			if err := add(query.name, q); err != nil {
				return nil, err
			}
		}
		badLabel := corpus.Vectors[bindingStart]
		badLabel.ID = fmt.Sprintf("profile-%d.tampered-original-label", profile)
		binding := *badLabel.Verification.Result.Binding
		binding.Proof.Nodes = append([]engine.NodeOpening{}, binding.Proof.Nodes...)
		last := len(binding.Proof.Nodes) - 1
		cell := bytes.Clone(binding.Proof.Nodes[last].Cell)
		_, n := binary.Uvarint(cell[1:])
		if n <= 0 || 1+n >= len(cell) {
			return nil, fmt.Errorf("missing label-bound conformance leaf")
		}
		cell[1+n] ^= 1
		binding.Proof.Nodes[last].Cell = cell
		badLabel.Verification.Result.Binding = &binding
		badLabel.Valid = false
		corpus.Vectors = append(corpus.Vectors, badLabel)
		retiredRoot := corpus.Vectors[bindingStart]
		retiredRoot.ID = fmt.Sprintf("profile-%d.retired-coordinate-root", profile)
		retiredRoot.Verification.Request.Root = cid.NewCidV1(0x300104, root.Hash()).String()
		retiredRoot.Valid = false
		corpus.Vectors = append(corpus.Vectors, retiredRoot)
		path := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: root.String(), Operation: "resolve", Steps: [][]byte{[]byte("missing"), []byte("suffix")}}
		if err := add("path-absence", path); err != nil {
			return nil, err
		}
		badPath := corpus.Vectors[len(corpus.Vectors)-1]
		badPath.ID = fmt.Sprintf("profile-%d.path-wrong-prefix", profile)
		badPath.Verification.Request.Steps = [][]byte{[]byte("a/b"), []byte("suffix")}
		badPath.Valid = false
		corpus.Vectors = append(corpus.Vectors, badPath)
		native := state
		native.Descriptor.DerivationProfile = uint8(derivation.Direct)
		native.Entries = append([]engine.Entry(nil), state.Entries...)
		for i, entry := range native.Entries {
			key, err := derivation.Derive(derivation.SHA256, entry.Label)
			if err != nil {
				return nil, err
			}
			native.Entries[i].Label = coordinate.EncodeKey(key.Key)
		}
		nativeRoot, err := e.Build(ctx, native, nodes)
		if err != nil {
			return nil, err
		}
		key := native.Entries[0].Label
		if err := add("native-key", protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: nativeRoot.String(), Steps: [][]byte{}, Operation: "binding", Label: &key}); err != nil {
			return nil, err
		}
		sequence := engine.State{Descriptor: maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: profile}, PayloadCID: cid.MustParse("bafkqaaa"), Entries: []engine.Entry{{Label: coordinate.EncodeIndex(0), Target: cid.MustParse("bafkqaaa")}}}
		listRoot, err := e.Build(ctx, sequence, nodes)
		if err != nil {
			return nil, err
		}
		start := uint64(0)
		end := uint64(1)
		if err := add("index-range", protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: listRoot.String(), Steps: [][]byte{}, Operation: "range", Start: &start, End: &end}); err != nil {
			return nil, err
		}
		maximum := coordinate.EncodeIndex(^uint64(0))
		if err := add("max-index-absence", protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: listRoot.String(), Steps: [][]byte{}, Operation: "binding", Label: &maximum}); err != nil {
			return nil, err
		}
		// A proof remains bound to the complete caller query, not a server echo.
		tampered := corpus.Vectors[len(corpus.Vectors)-1]
		tampered.ID = fmt.Sprintf("profile-%d.wrong-root", profile)
		tampered.Verification.Request.Root = root.String()
		tampered.Valid = false
		corpus.Vectors = append(corpus.Vectors, tampered)
	}
	data, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
