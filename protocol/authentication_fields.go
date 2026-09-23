package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	cid "github.com/ipfs/go-cid"
)

// encoding/json matches struct fields case-insensitively and treats null as
// absent for pointers. This profile requires exact names and present values.
// Duplicate keys and nesting are bounded before this walk; cryptographic and
// operation-specific checks run after it.
// Non-omitempty fields are required unless schema:"optional" declares the
// schema's default. Null values and null array items require explicit tags.
// Schema conformance tests keep these annotations aligned with the wire contract
// without changing Go's JSON output or adding a runtime schema interpreter.
func exactAuthenticationFields(raw []byte, t reflect.Type) error {
	return authenticationFields(raw, t, false, false)
}

func authenticationFields(raw []byte, t reflect.Type, nullable, nullableItems bool) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if nullable {
			return nil
		}
		return fmt.Errorf("null authentication field")
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == reflect.TypeFor[cid.Cid]() {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		if len(obj) != 1 || obj["/"] == nil {
			return fmt.Errorf("CID requires only / field")
		}
		var value string
		return json.Unmarshal(obj["/"], &value)
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			jsonOptions := strings.Split(field.Tag.Get("json"), ",")
			name := jsonOptions[0]
			if name != "" && name != "-" {
				fields[name] = field
				if !slices.Contains(jsonOptions[1:], "omitempty") &&
					!slices.Contains(strings.Split(field.Tag.Get("schema"), ","), "optional") && obj[name] == nil {
					return fmt.Errorf("missing authentication field %q", name)
				}
			}
		}
		for name, value := range obj {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("unknown authentication field %q", name)
			}
			options := strings.Split(field.Tag.Get("schema"), ",")
			if slices.Contains(strings.Split(field.Tag.Get("json"), ",")[1:], "string") {
				var text string
				if err := json.Unmarshal(value, &text); err != nil {
					return err
				}
				n, err := strconv.ParseUint(text, 10, 64)
				if err != nil || strconv.FormatUint(n, 10) != text {
					return fmt.Errorf("noncanonical uint64 field %q", name)
				}
			} else if err := authenticationFields(value, field.Type, slices.Contains(options, "nullable"), slices.Contains(options, "nullable-items")); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			var text string
			if err := json.Unmarshal(raw, &text); err != nil {
				return err
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(text)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != text {
				return fmt.Errorf("noncanonical base64 bytes")
			}
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := authenticationFields(value, t.Elem(), nullableItems, false); err != nil {
				return err
			}
		}
	}
	return nil
}
