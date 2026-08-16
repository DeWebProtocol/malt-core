package malt_test

import (
	"reflect"
	"testing"

	malt "github.com/dewebprotocol/malt-core"
)

func TestSegmentPathRoundTripAndConsume(t *testing.T) {
	path, err := malt.NewSegmentPath([]string{"a", "b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := path.String(), "a/b/c"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	prefix, err := malt.ParseSegmentPath("a/b")
	if err != nil {
		t.Fatal(err)
	}
	remaining, ok := path.Consume(prefix)
	if !ok {
		t.Fatal("Consume() rejected valid prefix")
	}
	if got, want := remaining.Segments(), []string{"c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("remaining = %#v, want %#v", got, want)
	}
}

func TestSegmentPathRejectsAmbiguousText(t *testing.T) {
	for _, raw := range []string{"/a", "a/", "a//b"} {
		if _, err := malt.ParseSegmentPath(raw); err == nil {
			t.Fatalf("ParseSegmentPath(%q) succeeded", raw)
		}
	}
	if _, err := malt.NewSegmentPath([]string{"a/b"}); err == nil {
		t.Fatal("NewSegmentPath accepted a segment containing the separator")
	}
}

func TestSegmentPathEmptyDenotesRoot(t *testing.T) {
	path, err := malt.ParseSegmentPath("")
	if err != nil {
		t.Fatal(err)
	}
	if !path.Empty() || path.String() != "" || len(path.Segments()) != 0 {
		t.Fatalf("empty path = %#v", path)
	}
}
