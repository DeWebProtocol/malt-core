package object

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	cid "github.com/ipfs/go-cid"
)

// CommitTagged commits exported fields explicitly tagged malt:"label". Each
// tagged field must contain an Object. A nil field is an error unless the tag
// includes omitempty. Untagged fields and malt:"-" are ignored. Empty labels,
// duplicate labels, unsupported options and tagged unexported fields are errors.
// Fields are never flattened, including embedded structs. Use Map for empty or
// arbitrary binary labels. Only field references, configuration and Payload are
// authenticated; other Go fields are not implicitly serialized.
func (b *Base) CommitTagged(ctx context.Context, self Object) (cid.Cid, error) {
	return withCommit(ctx, self, func(ctx context.Context) (*snapshot, error) {
		v := reflect.ValueOf(self).Elem()
		if v.Kind() != reflect.Struct {
			return nil, fmt.Errorf("tagged object must point to a struct")
		}
		refs, err := taggedReferences(v)
		if err != nil {
			return nil, err
		}
		return b.commitReferences(ctx, self, refs)
	})
}

func taggedReferences(v reflect.Value) ([]reference, error) {
	t := v.Type()
	refs := make([]reference, 0, t.NumField())
	labels := make(map[string]bool)
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag, tagged := field.Tag.Lookup("malt")
		if !tagged || tag == "-" {
			continue
		}
		if !field.IsExported() {
			return nil, fmt.Errorf("tagged field %s is not exported", field.Name)
		}
		parts := strings.Split(tag, ",")
		if parts[0] == "" || parts[0] == "-" {
			return nil, fmt.Errorf("field %s requires an explicit label", field.Name)
		}
		omitEmpty := false
		for _, option := range parts[1:] {
			if option != "omitempty" || omitEmpty {
				return nil, fmt.Errorf("field %s has unsupported tag options", field.Name)
			}
			omitEmpty = true
		}
		if labels[parts[0]] {
			return nil, fmt.Errorf("duplicate label %q", parts[0])
		}
		labels[parts[0]] = true
		value := v.Field(i)
		objectType := reflect.TypeFor[Object]()
		if !value.Type().Implements(objectType) {
			return nil, fmt.Errorf("field %s must implement Object", field.Name)
		}
		if value.Kind() == reflect.Interface && value.IsNil() {
			if omitEmpty {
				continue
			}
			return nil, fmt.Errorf("field %s contains a nil Object", field.Name)
		}
		target := value.Interface().(Object)
		if err := checkObject(target); err != nil {
			dynamic := reflect.ValueOf(target)
			if omitEmpty && dynamic.Kind() == reflect.Pointer && dynamic.IsNil() {
				continue
			}
			return nil, fmt.Errorf("field %s: %w", field.Name, err)
		}
		refs = append(refs, reference{label: []byte(parts[0]), target: target})
	}
	return refs, nil
}
