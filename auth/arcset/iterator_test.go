package arcset

import (
	"errors"
	"testing"

	cid "github.com/ipfs/go-cid"
)

type trackedArc struct {
	path   Path
	target cid.Cid
}
type trackedIterator struct {
	entries       []trackedArc
	index, closed int
	err           error
}

func (i *trackedIterator) Next() (Path, cid.Cid, bool) {
	if i.index == len(i.entries) {
		return "", cid.Undef, false
	}
	entry := i.entries[i.index]
	i.index++
	return entry.path, entry.target, true
}
func (i *trackedIterator) Err() error { return i.err }
func (i *trackedIterator) Close()     { i.closed++ }

type trackedArcSet struct{ iterator *trackedIterator }

func (s trackedArcSet) Get(Path) (cid.Cid, bool) { return cid.Undef, false }
func (s trackedArcSet) Len() int                 { return len(s.iterator.entries) }
func (s trackedArcSet) Iterate() Iterator        { return s.iterator }

func TestToPathMapClosesIteratorOnEveryExit(t *testing.T) {
	target, other := testCID(t, "target"), testCID(t, "other")
	readErr := errors.New("read failed")
	for _, tc := range []struct {
		name             string
		entries          []trackedArc
		readErr, wantErr error
	}{
		{name: "success", entries: []trackedArc{{"a", target}}},
		{name: "empty"},
		{name: "invalid path", entries: []trackedArc{{"", target}}, wantErr: ErrEmptyPath},
		{name: "duplicate path", entries: []trackedArc{{"a", target}, {"a", other}}, wantErr: ErrDuplicatePath},
		{name: "read error", readErr: readErr, wantErr: readErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iterator := &trackedIterator{entries: tc.entries, err: tc.readErr}
			values, err := ToPathMap(trackedArcSet{iterator: iterator})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if iterator.closed != 1 {
				t.Fatalf("Close called %d times", iterator.closed)
			}
			if err == nil && len(values) != len(tc.entries) {
				t.Fatal("lost successful entries")
			}
		})
	}
}
