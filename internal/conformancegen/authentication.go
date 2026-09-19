package conformancegen

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/auth/input"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// GenerateAuthentication is a separate V=0 corpus. Historical corpora remain
// generated with their exact original Root and proof formats.
func GenerateAuthentication() ([]byte, error) {
	type vector struct {
		ID           string                              `json:"id"`
		Verification protocol.AuthenticationVerification `json:"verification"`
		Valid        bool                                `json:"valid"`
	}
	corpus := struct {
		Schema  string   `json:"schema"`
		Vectors []vector `json:"vectors"`
	}{Schema: "malt.conformance.authentication/0", Vectors: []vector{}}
	ctx := context.Background()
	for _, profile := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		var scheme engine.ProfileVerifier
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
		e := engine.New(input.DefaultRegistry(), profiles)
		nodes := memory.NewNodes()
		state := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: profile}, Entries: []engine.Entry{{Input: input.LabelValue([]byte("a/b")), Target: cid.MustParse("bafkqaaa")}, {Input: input.SystemValue(input.Payload), Target: cid.MustParse("bafkqaaa")}}}
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
		for _, query := range []struct {
			name  string
			value input.Value
		}{{"opaque-label", input.LabelValue([]byte("a/b"))}, {"system-payload", input.SystemValue(input.Payload)}, {"literal-at-payload-absent", input.LabelValue([]byte("@payload"))}, {"missing", input.LabelValue([]byte("absent"))}} {
			value := query.value
			q := protocol.AuthenticationRequest{Profile: protocol.AuthenticationProfile, Root: root.String(), Steps: []input.Value{}, Operation: "binding", Input: &value}
			if err := add(query.name, q); err != nil {
				return nil, err
			}
		}
		path := protocol.AuthenticationRequest{Profile: protocol.AuthenticationPathProfile, Root: root.String(), Operation: "resolve", Steps: []input.Value{input.LabelValue([]byte("missing")), input.LabelValue([]byte("suffix"))}}
		if err := add("path-absence", path); err != nil {
			return nil, err
		}
		badPath := corpus.Vectors[len(corpus.Vectors)-1]
		badPath.ID = fmt.Sprintf("profile-%d.path-wrong-prefix", profile)
		badPath.Verification.Request.Steps = []input.Value{input.LabelValue([]byte("a/b")), input.LabelValue([]byte("suffix"))}
		badPath.Valid = false
		corpus.Vectors = append(corpus.Vectors, badPath)
		native := state
		native.Descriptor.InputRule = 0
		native.Entries = append([]engine.Entry(nil), state.Entries...)
		for i, entry := range native.Entries {
			key, err := e.Rules.Derive(input.BytesSHA256, entry.Input)
			if err != nil {
				return nil, err
			}
			native.Entries[i].Input = input.KeyValue(key.Key)
		}
		nativeRoot, err := e.Build(ctx, native, nodes)
		if err != nil {
			return nil, err
		}
		key := native.Entries[0].Input
		if err := add("native-key", protocol.AuthenticationRequest{Profile: protocol.AuthenticationProfile, Root: nativeRoot.String(), Steps: []input.Value{}, Operation: "binding", Input: &key}); err != nil {
			return nil, err
		}
		sequence := engine.State{Descriptor: maltcid.RootDescriptor{Layout: maltcid.Positional, Profile: profile}, ChunkSize: 8, TotalSize: 5, Entries: []engine.Entry{{Input: input.IndexValue(0), Target: cid.MustParse("bafkqaaa")}}}
		listRoot, err := e.Build(ctx, sequence, nodes)
		if err != nil {
			return nil, err
		}
		start := uint64(1)
		end := uint64(4)
		if err := add("measured-range", protocol.AuthenticationRequest{Profile: protocol.AuthenticationProfile, Root: listRoot.String(), Steps: []input.Value{}, Operation: "range", Start: &start, End: &end}); err != nil {
			return nil, err
		}
		maximum := input.IndexValue(^uint64(0))
		if err := add("max-index-absence", protocol.AuthenticationRequest{Profile: protocol.AuthenticationProfile, Root: listRoot.String(), Steps: []input.Value{}, Operation: "binding", Input: &maximum}); err != nil {
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
