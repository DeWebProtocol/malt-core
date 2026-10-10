package tree

import (
	"bytes"
	"encoding/binary"
	"testing"

	cid "github.com/ipfs/go-cid"
)

func TestPrefixLabelCellRequiresCanonicalFraming(t *testing.T) {
	value := cid.MustParse("bafkqaaa")
	for _, label := range [][]byte{{}, {0xff, 0, 0x80}, bytes.Repeat([]byte{0x80}, 128)} {
		cell := prefixCell(binding{label: label, target: value})
		got, target, err := parsePrefix(cell)
		if err != nil || got == nil || !bytes.Equal(got, label) || !target.Equals(value) {
			t.Fatalf("label framing: label=%x got=%x target=%s err=%v", label, got, target, err)
		}
	}
	malformed := [][]byte{
		nil,
		{prefixLeaf},
		{prefixLeaf, 0x80},
		append([]byte{prefixLeaf, 0x80, 0}, value.Bytes()...), // Nonminimal zero length.
		append([]byte{prefixLeaf, 0x81, 0, 'a'}, value.Bytes()...),
		{prefixLeaf, 1, 'a'}, // No target.
		{prefixLeaf, 2, 'a'}, // Truncated label.
		binary.AppendUvarint([]byte{prefixLeaf}, ^uint64(0)),
		append([]byte{prefixLeaf, 0}, append(value.Bytes(), 0)...), // Trailing CID bytes.
		{childNode, 0, 1},
	}
	for _, cell := range malformed {
		if _, _, err := parsePrefix(cell); err == nil {
			t.Fatalf("accepted malformed leaf %x", cell)
		}
	}
}
