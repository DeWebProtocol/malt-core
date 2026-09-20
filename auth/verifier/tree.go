package verifier

import (
	"github.com/dewebprotocol/malt-core/auth/commitment"
	structure "github.com/dewebprotocol/malt-core/auth/semantic"
	"github.com/dewebprotocol/malt-core/auth/semantic/layoutcompat"
	"github.com/dewebprotocol/malt-core/auth/semantic/list"
	"github.com/dewebprotocol/malt-core/auth/semantic/nodegeometry"
	cid "github.com/ipfs/go-cid"
)

type treeListVerifier struct{ scheme commitment.IndexVerifier }

func newTreeListVerifier(scheme commitment.IndexVerifier, _ nodegeometry.Geometry) ListVerifier {
	return &treeListVerifier{scheme: scheme}
}
func (v *treeListVerifier) Verify(root cid.Cid, index uint64, expected list.Query, proof structure.Proof) (bool, error) {
	e, _, err := layoutcompat.Engine(v.scheme, nil)
	if err != nil {
		return false, err
	}
	return layoutcompat.VerifyPositional(e, root, index, expected, proof)
}
func (v *treeListVerifier) VerifyRange(root cid.Cid, start uint64, end *uint64, expected list.RangeResult, proof structure.Proof) (bool, error) {
	e, _, err := layoutcompat.Engine(v.scheme, nil)
	if err != nil {
		return false, err
	}
	return layoutcompat.VerifyRange(e, root, start, end, expected, proof)
}
