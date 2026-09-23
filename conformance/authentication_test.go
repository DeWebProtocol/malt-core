package conformance_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/dewebprotocol/malt-core/internal/conformancegen"
	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/sdk/authentication"
	authbuiltin "github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
)

func TestAuthenticationV0Corpus(t *testing.T) {
	raw, err := os.ReadFile("authentication-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	regenerated, err := conformancegen.GenerateAuthentication()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, regenerated) {
		t.Fatal("V=0 authentication corpus differs from deterministic generator")
	}
	var corpus struct {
		Schema  string `json:"schema"`
		Vectors []struct {
			ID           string          `json:"id"`
			Verification json.RawMessage `json:"verification"`
			Valid        bool            `json:"valid"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "malt.conformance.authentication/2" || len(corpus.Vectors) == 0 {
		t.Fatal("invalid corpus")
	}
	verifier, err := authbuiltin.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			wire, err := protocol.DecodeAuthenticationVerification(vector.Verification)
			valid := false
			if err == nil {
				valid, err = authentication.Verify(verifier, wire.Request, wire.Result)
			}
			if (err == nil && valid) != vector.Valid {
				t.Fatalf("valid=%v error=%v", valid, err)
			}
		})
	}
}
