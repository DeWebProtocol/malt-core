package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/dewebprotocol/malt-core/auth/input"
	cid "github.com/ipfs/go-cid"
	"reflect"
	"strconv"
	"strings"
)

// encoding/json matches struct fields case-insensitively and treats null as
// absent for pointers. This profile requires exact names and present values.
// Duplicate keys and nesting are bounded before this walk; cryptographic and
// operation-specific checks run after it.
func exactAuthenticationFields(raw []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("explicit null optional field")
		}
	}
	if t == reflect.TypeOf(input.Value{}) {
		var value input.Value
		return json.Unmarshal(raw, &value)
	}
	if t == reflect.TypeOf(cid.Cid{}) {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
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
	if t.Kind() != reflect.Slice && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("null authentication field")
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
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag != "" && tag != "-" {
				fields[tag] = field
			}
		}
		for name, value := range obj {
			field, ok := fields[name]
			if !ok {
				return fmt.Errorf("unknown authentication field %q", name)
			}
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && field.Type.Kind() != reflect.Slice && field.Type != reflect.TypeOf(cid.Cid{}) {
				return fmt.Errorf("null authentication field %q", name)
			}
			if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("null byte field %q", name)
			}
			if strings.Contains(","+field.Tag.Get("json")+",", ",string,") {
				var text string
				if err := json.Unmarshal(value, &text); err != nil {
					return err
				}
				n, err := strconv.ParseUint(text, 10, 64)
				if err != nil || strconv.FormatUint(n, 10) != text {
					return fmt.Errorf("noncanonical uint64 field %q", name)
				}
			} else if err := exactAuthenticationFields(value, field.Type); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := exactAuthenticationFields(value, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
