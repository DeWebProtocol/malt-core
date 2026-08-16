package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	commitmentipa "github.com/dewebprotocol/malt-core/auth/commitment/ipa"
)

func TestWriteParameterExport(t *testing.T) {
	var output bytes.Buffer
	if err := writeParameterExport(&output); err != nil {
		t.Fatalf("writeParameterExport: %v", err)
	}

	decoder := json.NewDecoder(&output)
	var got map[string]string
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("decode parameter export: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("parameter export fields = %v, want exactly id and sha256", got)
	}
	if got["id"] != commitmentipa.ParameterSetID {
		t.Fatalf("id = %q, want %q", got["id"], commitmentipa.ParameterSetID)
	}
	if got["sha256"] != commitmentipa.ParameterSHA256() {
		t.Fatalf("sha256 = %q, want %q", got["sha256"], commitmentipa.ParameterSHA256())
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("trailing parameter export data: %v", err)
	}
}
