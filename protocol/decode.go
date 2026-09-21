package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// MaxVerificationJSONBytes bounds current authentication JSON before decoding.
const MaxVerificationJSONBytes = 96 << 20

func decodeVerificationJSON(data []byte, target any) error {
	if len(data) == 0 {
		return fmt.Errorf("verification JSON is empty")
	}
	if len(data) > MaxVerificationJSONBytes {
		return fmt.Errorf("verification JSON exceeds %d bytes", MaxVerificationJSONBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return fmt.Errorf("unexpected trailing JSON: %w", err)
	}
	return nil
}
