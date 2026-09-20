package host

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestSessionSnapshotRoundTripAndAuthentication(t *testing.T) {
	computer, err := newComputer("kzg")
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSession(computer)
	if err != nil {
		t.Fatal(err)
	}
	Bootstrap, err := source.Bootstrap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	Snapshot, err := source.Snapshot(key)
	if err != nil {
		t.Fatal(err)
	}
	source.Close()

	restored, err := NewSession(computer)
	if err != nil {
		t.Fatal(err)
	}
	view, err := restored.Restore(context.Background(), Snapshot, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(view, Bootstrap) {
		t.Fatalf("restored view differs:\n got: %s\nwant: %s", view, Bootstrap)
	}
	if _, err := restored.Snapshot(key); err != nil {
		t.Fatalf("snapshot restored session: %v", err)
	}

	wrongKey, err := NewSession(computer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongKey.Restore(
		context.Background(),
		Snapshot,
		[]byte("fedcba9876543210fedcba9876543210"),
	); err == nil {
		t.Fatal("snapshot restored with the wrong checkpoint key")
	}

	var envelope map[string]any
	if err := json.Unmarshal(Snapshot, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["materialization_sha256"] = "00"
	tampered, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	corrupt, err := NewSession(computer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := corrupt.Restore(context.Background(), tampered, key); err == nil {
		t.Fatal("snapshot restored after materialization digest mutation")
	}
}
