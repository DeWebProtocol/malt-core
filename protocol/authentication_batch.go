package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-core/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	AuthenticationBatchProfile    = "malt.authentication-batch/1"
	AuthenticationReceiptProfile  = "malt.authentication-receipt/1"
	MaxAuthenticationBatchObjects = 4096
)

// AuthenticationBatch submits locally computed candidates in dependency order.
// A batch is an operational request, not a proof of a state transition. Base
// identifies the caller's selected starting Root; Root names the final candidate.
// Callers own application projection, durable storage, publication and trust.
type AuthenticationBatch struct {
	Profile       string                    `json:"profile"`
	TransactionID string                    `json:"transaction_id"`
	Base          string                    `json:"base"`
	Root          string                    `json:"root"`
	Candidates    []AuthenticationCandidate `json:"candidates"`
}

// AuthenticationReceipt acknowledges durable materialization of one exact
// batch. It is neither a signature nor evidence of trusted-root acceptance.
type AuthenticationReceipt struct {
	Profile         string `json:"profile"`
	TransactionID   string `json:"transaction_id"`
	Base            string `json:"base"`
	Root            string `json:"root"`
	Digest          string `json:"digest"`
	DurableBoundary string `json:"durable_boundary"`
}

func authenticationRoot(raw string) error {
	value, err := cid.Decode(raw)
	if err != nil || value.String() != raw {
		return errors.New("expected a canonical Root CID")
	}
	_, _, err = maltcid.ParseRoot(value)
	return err
}

func (b AuthenticationBatch) Validate() error {
	if b.Profile != AuthenticationBatchProfile {
		return errors.New("unsupported authentication batch profile")
	}
	if len(b.TransactionID) == 0 || len(b.TransactionID) > 128 {
		return errors.New("transaction ID must contain 1..128 ASCII identifier bytes")
	}
	for _, c := range []byte(b.TransactionID) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return errors.New("invalid transaction ID")
		}
	}
	if err := authenticationRoot(b.Base); err != nil {
		return fmt.Errorf("batch base: %w", err)
	}
	if err := authenticationRoot(b.Root); err != nil {
		return fmt.Errorf("batch Root: %w", err)
	}
	if len(b.Candidates) == 0 || len(b.Candidates) > MaxAuthenticationBatchObjects {
		return errors.New("authentication batch object count is outside bounds")
	}
	positions := make(map[string]int, len(b.Candidates))
	for i, c := range b.Candidates {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("candidate %d: %w", i, err)
		}
		if err := authenticationRoot(c.Root); err != nil {
			return fmt.Errorf("candidate %d Root: %w", i, err)
		}
		if c.Previous != "" {
			if err := authenticationRoot(c.Previous); err != nil {
				return fmt.Errorf("candidate %d previous: %w", i, err)
			}
		}
		if _, ok := positions[c.Root]; ok {
			return errors.New("duplicate authentication candidate Root")
		}
		positions[c.Root] = i
	}
	if b.Candidates[len(b.Candidates)-1].Root != b.Root {
		return errors.New("final candidate must be the selected batch Root")
	}
	for i, c := range b.Candidates {
		if j, ok := positions[c.Previous]; ok && j >= i {
			return errors.New("authentication candidates must follow their lineage bases")
		}
		for _, entry := range c.State.Entries {
			if j, ok := positions[entry.Target.String()]; ok && j >= i {
				return errors.New("authentication candidates must precede their parents")
			}
		}
	}
	return nil
}

// Digest hashes the normalized Go JSON projection of the complete batch, with
// an explicit profile prefix. SDK hosts expose this calculation so adapters do
// not implement a second canonical encoding. Candidate ordering is significant.
func (b AuthenticationBatch) Digest() (string, error) {
	if err := b.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte(AuthenticationBatchProfile + "\x00"))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (r AuthenticationReceipt) Validate(b AuthenticationBatch) error {
	digest, err := b.Digest()
	if err != nil {
		return err
	}
	if r.Profile != AuthenticationReceiptProfile || r.TransactionID != b.TransactionID || r.Base != b.Base || r.Root != b.Root || r.Digest != digest || strings.TrimSpace(r.DurableBoundary) == "" {
		return errors.New("receipt does not acknowledge the exact authentication batch")
	}
	return nil
}

func DecodeAuthenticationBatch(data []byte) (AuthenticationBatch, error) {
	var b AuthenticationBatch
	if err := decodeAuthenticationJSON(data, &b); err != nil {
		return b, err
	}
	return b, b.Validate()
}

func DecodeAuthenticationReceipt(data []byte) (AuthenticationReceipt, error) {
	var r AuthenticationReceipt
	err := decodeAuthenticationJSON(data, &r)
	return r, err
}
