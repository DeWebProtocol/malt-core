package object

import (
	"reflect"
	"testing"
)

func TestTagValidation(t *testing.T) {
	for name, value := range map[string]any{
		"empty label": struct {
			V Object `malt:""`
		}{},
		"missing label": struct {
			V Object `malt:",omitempty"`
		}{},
		"unknown option": struct {
			V Object `malt:"v,unknown"`
		}{},
		"duplicate option": struct {
			V Object `malt:"v,omitempty,omitempty"`
		}{},
		"duplicate label even when omitted": struct {
			A Object `malt:"v,omitempty"`
			B Object `malt:"v,omitempty"`
		}{},
		"non-object": struct {
			V string `malt:"v,omitempty"`
		}{},
		"unexported": struct {
			v Object `malt:"v"`
		}{},
		"nil interface": struct {
			V Object `malt:"v"`
		}{},
		"typed nil": struct {
			V *Map `malt:"v"`
		}{},
		"typed nil in interface": struct {
			V Object `malt:"v"`
		}{V: (*Map)(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := taggedReferences(reflect.ValueOf(value)); err == nil {
				t.Fatal("invalid tag/field accepted")
			}
		})
	}
	for _, value := range []any{
		struct {
			V Object `malt:"v,omitempty"`
		}{},
		struct {
			V *Map `malt:"v,omitempty"`
		}{},
		struct {
			V Object `malt:"v,omitempty"`
		}{V: (*Map)(nil)},
		struct {
			V        string `malt:"-"`
			Untagged *Map
		}{},
	} {
		refs, err := taggedReferences(reflect.ValueOf(value))
		if err != nil || len(refs) != 0 {
			t.Fatalf("omitted fields: %v, %v", refs, err)
		}
	}
}
