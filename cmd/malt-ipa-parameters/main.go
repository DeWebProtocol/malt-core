// Command malt-ipa-parameters prints the current IPA parameter fingerprint as
// stable, machine-readable JSON for release provenance tooling.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	commitmentipa "github.com/dewebprotocol/malt-core/auth/commitment/ipa"
)

type parameterExport struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

func writeParameterExport(w io.Writer) error {
	return json.NewEncoder(w).Encode(parameterExport{
		ID:     commitmentipa.ParameterSetID,
		SHA256: commitmentipa.ParameterSHA256(),
	})
}

func main() {
	if err := writeParameterExport(os.Stdout); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "write IPA parameter fingerprint: %v\n", err)
		os.Exit(1)
	}
}
