// Package derivation converts opaque application labels to authentication
// coordinates. It is shared by writers, provers, verifiers and cold recovery.
package derivation

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/coordinate"
)

type ProfileID uint8

// IDs 0, 1 and 2 belong to retired typed-input profiles. Their meanings must
// never be reassigned. These profiles operate only on opaque label bytes.
const (
	Direct ProfileID = 3
	SHA256 ProfileID = 4
)

func Supported(profile ProfileID) bool { return profile == Direct || profile == SHA256 }

// Derive performs no application normalization, path parsing or reserved-name
// interpretation. Direct parses the label's canonical coordinate encoding.
// SHA256 hashes domain || uvarint(label length) || label, yielding a Prefix key.
func Derive(profile ProfileID, label []byte) (coordinate.Coordinate, error) {
	switch profile {
	case Direct:
		return coordinate.Parse(label)
	case SHA256:
		encoded := []byte("malt:coordinate:sha256:0\x00")
		encoded = binary.AppendUvarint(encoded, uint64(len(label)))
		encoded = append(encoded, label...)
		return coordinate.Coordinate{Kind: coordinate.Key, Key: sha256.Sum256(encoded)}, nil
	default:
		return coordinate.Coordinate{}, fmt.Errorf("unsupported coordinate derivation profile %d", profile)
	}
}
