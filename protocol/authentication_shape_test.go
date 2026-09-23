package protocol_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestAuthenticationResultRequiredFieldsAndNulls(t *testing.T) {
	root, err := maltcid.NewRoot(maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf(`{"profile":"malt.authentication/3","resolved":%q,`, root.String())
	binding := `{"present":false,"target":null,"proof":{"format":"malt.binding/0","nodes":[{}]}}`
	rangeResult := `{"metadata":{"height":"0","count":"0","chunk_size":"1","total_size":"0"},"metadata_evidence":` + binding + `,"segments":[]}`
	valid := prefix + `"traversal":{"results":[]},"range":` + rangeResult + `}`
	for _, raw := range []string{
		prefix + `"traversal":{"results":[]}}`,
		valid,
		prefix + `"traversal":{"results":[]},"binding":` + binding + `}`,
		prefix + `"traversal":{"results":[]},"binding":` + strings.ReplaceAll(binding, `"target":null,`, "") + `}`,
	} {
		if _, err := protocol.DecodeAuthenticationResult([]byte(raw)); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{
		prefix[:len(prefix)-1] + `}`,
		prefix + `"traversal":{}}`,
		prefix + `"traversal":null}`,
		prefix + `"traversal":{"results":null}}`,
		prefix + `"traversal":{"results":[null]}}`,
		prefix + `"traversal":{"results":[]},"binding":` + strings.ReplaceAll(binding, `"present":false,`, "") + `}`,
		strings.Replace(valid, `"height":"0",`, "", 1),
		strings.Replace(valid, `"segments":[]`, `"segments":null`, 1),
		strings.Replace(valid, `"nodes":[{}]`, `"nodes":null`, 1),
		strings.Replace(valid, `"nodes":[{}]`, `"nodes":[null]`, 1),
		strings.Replace(valid, `"nodes":[{}]`, `"nodes":[{"cell":null}]`, 1),
		strings.Replace(valid, `"nodes":[{}]`, `"nodes":[{"cell":[1,2]}]`, 1),
		strings.Replace(valid, `"nodes":[{}]`, `"nodes":[{"metadata_proof":null}]`, 1),
	} {
		if _, err := protocol.DecodeAuthenticationResult([]byte(raw)); err == nil {
			t.Fatal("accepted malformed result", raw)
		}
	}
}

func TestAuthenticationCandidateNullCellsAndOptionalDefaults(t *testing.T) {
	descriptor := maltcid.RootDescriptor{DerivationProfile: uint8(derivation.Direct), Layout: maltcid.Positional, Profile: maltcid.IPA256}
	root, err := maltcid.NewRoot(descriptor, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	ref, _, err := maltcid.RootNode(root)
	if err != nil {
		t.Fatal(err)
	}
	reference, err := ref.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	candidate := protocol.AuthenticationCandidate{Profile: protocol.AuthenticationProfile, Root: root.String(), State: engine.State{Descriptor: descriptor}, Nodes: []protocol.AuthenticationNode{{Reference: reference, Cells: make([][]byte, 256)}}}
	raw, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	// Empty slots really are null; only the enclosing vector must be an array.
	decoded, err := protocol.DecodeAuthenticationCandidate(raw)
	if err != nil || len(decoded.Nodes[0].Cells) != 256 {
		t.Fatalf("null cells: %v", err)
	}
	if _, err := protocol.DecodeAuthenticationCandidate([]byte(strings.Replace(string(raw), `"entries":null`, `"entries":[null]`, 1))); err == nil {
		t.Fatal("accepted null entry")
	}
	for _, state := range []string{
		`{"descriptor":{"layout":2,"derivation_profile":3,"vc_profile":2}}`,
		`{"descriptor":{"layout":2,"derivation_profile":3,"vc_profile":2},"entries":null}`,
		`{"descriptor":{"layout":2,"derivation_profile":3,"vc_profile":2},"entries":[]}`,
	} {
		if _, err := protocol.DecodeAuthenticationState([]byte(state)); err != nil {
			t.Fatal("schema defaults rejected", state, err)
		}
	}
	candidate.Nodes[0].Cells = nil
	raw, err = json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.DecodeAuthenticationCandidate(raw); err == nil {
		t.Fatal("accepted null vector")
	}
	if _, err := protocol.DecodeAuthenticationReceipt([]byte(`{}`)); err == nil {
		t.Fatal("accepted missing receipt fields")
	}
}

// Check the Go field-shape annotations against the independently published
// schemas. This prevents a new struct field or changed schema from silently
// restoring decoder/schema differences. Semantic and cryptographic validation
// remains in the operation-specific contracts.
func TestAuthenticationFieldShapesMatchSchemas(t *testing.T) {
	documents := map[string]map[string]any{}
	var resolve func(string, map[string]any) (string, map[string]any)
	resolve = func(file string, schema map[string]any) (string, map[string]any) {
		for {
			ref, ok := schema["$ref"].(string)
			if !ok {
				return file, schema
			}
			name, fragment, _ := strings.Cut(ref, "#")
			if name != "" {
				file = name
			}
			doc := documents[file]
			if doc == nil {
				raw, err := protocol.Schema(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(raw, &doc); err != nil {
					t.Fatal(err)
				}
				documents[file] = doc
			}
			schema = doc
			for _, part := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
				if part != "" {
					schema = schema[part].(map[string]any)
				}
			}
		}
	}
	var nullable func(map[string]any) bool
	nullable = func(schema map[string]any) bool {
		if schema["type"] == "null" {
			return true
		}
		if types, ok := schema["type"].([]any); ok && slices.Contains(types, any("null")) {
			return true
		}
		for _, union := range []string{"anyOf", "oneOf"} {
			if choices, ok := schema[union].([]any); ok {
				for _, choice := range choices {
					if nullable(choice.(map[string]any)) {
						return true
					}
				}
			}
		}
		return false
	}
	var check func(reflect.Type, string, map[string]any)
	check = func(typ reflect.Type, file string, schema map[string]any) {
		file, schema = resolve(file, schema)
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if typ == reflect.TypeFor[[]byte]() || typ == reflect.TypeFor[cid.Cid]() {
			return
		}
		if typ.Kind() == reflect.Slice {
			if typ.Elem().Kind() != reflect.Uint8 {
				check(typ.Elem(), file, schema["items"].(map[string]any))
			}
			return
		}
		if typ.Kind() != reflect.Struct {
			return
		}
		properties := schema["properties"].(map[string]any)
		required, _ := schema["required"].([]any)
		fields := 0
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			tags := strings.Split(field.Tag.Get("json"), ",")
			name := tags[0]
			if name == "" || name == "-" {
				continue
			}
			fields++
			property, ok := properties[name].(map[string]any)
			if !ok {
				t.Fatalf("%s.%s has no schema property", typ, name)
			}
			propertyFile, property := resolve(file, property)
			options := strings.Split(field.Tag.Get("schema"), ",")
			optional := slices.Contains(tags[1:], "omitempty") || slices.Contains(options, "optional")
			if optional == slices.Contains(required, any(name)) {
				t.Errorf("%s.%s required mismatch", typ, name)
			}
			if slices.Contains(options, "nullable") != nullable(property) {
				t.Errorf("%s.%s nullability mismatch", typ, name)
			}
			if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() != reflect.Uint8 {
				_, item := resolve(propertyFile, property["items"].(map[string]any))
				if slices.Contains(options, "nullable-items") != nullable(item) {
					t.Errorf("%s.%s item nullability mismatch", typ, name)
				}
			}
			check(field.Type, propertyFile, property)
		}
		if fields != len(properties) {
			t.Errorf("%s schema has unrepresented fields", typ)
		}
	}
	for _, tc := range []struct {
		file string
		typ  reflect.Type
	}{
		{"authentication-request.schema.json", reflect.TypeFor[protocol.AuthenticationRequest]()},
		{"authentication-result.schema.json", reflect.TypeFor[protocol.AuthenticationResult]()},
		{"authentication-verification.schema.json", reflect.TypeFor[protocol.AuthenticationVerification]()},
		{"authentication-state.schema.json", reflect.TypeFor[engine.State]()},
		{"authentication-candidate.schema.json", reflect.TypeFor[protocol.AuthenticationCandidate]()},
		{"authentication-batch.schema.json", reflect.TypeFor[protocol.AuthenticationBatch]()},
		{"authentication-receipt.schema.json", reflect.TypeFor[protocol.AuthenticationReceipt]()},
		{"authentication-delta.schema.json", reflect.TypeFor[protocol.AuthenticationDelta]()},
	} {
		t.Run(tc.file, func(t *testing.T) { check(tc.typ, tc.file, map[string]any{"$ref": tc.file}) })
	}
}
