package verifier

import (
	"github.com/dewebprotocol/malt-core/auth/arcset"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/layoutcompat"
	"github.com/dewebprotocol/malt-core/auth/semantic/mapping"
	cid "github.com/ipfs/go-cid"
)

type radixMapVerifier struct{ scheme commitment.IndexVerifier }

func newRadixMapVerifier(scheme commitment.IndexVerifier) MapVerifier {
	return &radixMapVerifier{scheme: scheme}
}
func (v *radixMapVerifier) Verify(root cid.Cid, key arcset.Path, expected mapping.Binding, proof structure.Proof) (bool, error) {
	e, _, err := layoutcompat.Engine(v.scheme, nil)
	if err != nil {
		return false, err
	}
	return layoutcompat.VerifyPrefix(e, root, key, expected, proof)
}
