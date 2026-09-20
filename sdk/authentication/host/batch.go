package host

import (
	"context"

	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
)

// ValidateBatch checks every candidate and returns the exact batch digest.
func (c *Computer) ValidateBatch(ctx context.Context, data []byte) ([]byte, error) {
	e, err := c.authenticationEngine()
	if err != nil {
		return nil, err
	}
	batch, err := protocol.DecodeAuthenticationBatch(data)
	if err != nil {
		return nil, err
	}
	if err := authentication.ValidateBatch(ctx, e, batch); err != nil {
		return nil, err
	}
	digest, err := batch.Digest()
	return []byte(digest), err
}

// ValidateReceipt binds an operational acknowledgement to the caller's exact
// batch. It neither modifies retained handles nor accepts a trusted Root.
func ValidateReceipt(batchJSON, receiptJSON []byte) ([]byte, error) {
	batch, err := protocol.DecodeAuthenticationBatch(batchJSON)
	if err != nil {
		return nil, err
	}
	receipt, err := protocol.DecodeAuthenticationReceipt(receiptJSON)
	if err != nil {
		return nil, err
	}
	if err := receipt.Validate(batch); err != nil {
		return nil, err
	}
	return []byte(batch.Root), nil
}
