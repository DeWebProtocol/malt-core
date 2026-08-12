package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCommittedAssetsMatchPinnedTrustedSetup(t *testing.T) {
	verifier, writer, err := generateFromPinnedModule()
	if err != nil {
		t.Fatalf("generateFromPinnedModule: %v", err)
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	packageDir := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	assertCommittedAsset(t, filepath.Join(packageDir, "trusted_setup_verifier.bin"), verifier)
	assertCommittedAsset(t, filepath.Join(packageDir, "trusted_setup_writer.bin"), writer)
}

func assertCommittedAsset(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s does not match the pinned, validated trusted setup; run make generate-kzg-setup", path)
	}
}
