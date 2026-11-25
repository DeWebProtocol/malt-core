package tree

import (
	"bytes"
	"testing"

	"github.com/dewebprotocol/malt-core/maltcid"
)

func TestChildCellInheritsTreeContext(t *testing.T) {
	for _, layout := range []maltcid.Layout{maltcid.Map, maltcid.List} {
		for _, profileID := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
			profile, err := maltcid.Profile(profileID)
			if err != nil {
				t.Fatal(err)
			}
			raw := bytes.Repeat([]byte{0xab}, profile.CommitmentSize)
			cell := childCell(raw)
			if !bytes.Equal(cell, append([]byte{0x02}, raw...)) {
				t.Fatalf("unexpected child cell for profile %d: %x", profileID, cell)
			}
			parent := maltcid.NodeRef{Layout: layout, Profile: profileID}
			child, err := parseChild(cell, parent)
			if err != nil || child.Layout != layout || child.Profile != profileID || !bytes.Equal(child.Commitment, raw) {
				t.Fatalf("child reference for layout %d, profile %d: %+v, %v", layout, profileID, child, err)
			}
			for _, invalid := range [][]byte{cell[:len(cell)-1], append(cell, 0), append([]byte{mapLeaf}, raw...)} {
				if _, err := parseChild(invalid, parent); err == nil {
					t.Fatalf("accepted malformed child cell for profile %d: %x", profileID, invalid)
				}
			}
		}
	}
}
