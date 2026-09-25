// Command range authenticates a fixed-chunk byte range and checks its payload.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/coordinate"
	"github.com/dewebprotocol/malt-core/derivation"
	"github.com/dewebprotocol/malt-core/engine"
	"github.com/dewebprotocol/malt-core/maltcid"
	"github.com/dewebprotocol/malt-core/sdk/authentication/builtin"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()
	scheme, err := ipa.NewCommitterScheme(ipa.ProfileDirect)
	if err != nil {
		return err
	}
	profiles := engine.NewRegistry()
	if err := profiles.Register(scheme); err != nil {
		return err
	}
	prover := engine.New(profiles)

	// 1. Commit: the application chunks "hello world" into four-byte blocks. The last
	// block may be shorter. Core authenticates the CIDs and the byte geometry.
	chunks := [][]byte{[]byte("hell"), []byte("o wo"), []byte("rld")}
	payloads := make(map[string][]byte)
	state := engine.State{
		Descriptor: maltcid.RootDescriptor{
			Layout: maltcid.Positional, DerivationProfile: uint8(derivation.Direct), Profile: maltcid.IPA256,
		},
		ChunkSize: 4, TotalSize: 11,
	}
	for index, chunk := range chunks {
		target, err := (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}).Sum(chunk)
		if err != nil {
			return err
		}
		// Direct indices are exactly eight unsigned big-endian bytes, not text.
		state.Entries = append(state.Entries, engine.Entry{
			Label: coordinate.EncodeIndex(uint64(index)), Target: target,
		})
		payloads[target.String()] = chunk
	}
	view, err := prover.Interpret(state)
	if err != nil {
		return err
	}
	nodes := memory.NewNodes()
	root, err := prover.Commit(ctx, view, nodes)
	if err != nil {
		return err
	}
	fmt.Println("Commit: sequence Root created")

	// 2. Prove: [start, end) is a byte interval, distinct from index labels.
	start, end := uint64(3), uint64(9)
	result, err := prover.ProveRange(ctx, root, start, &end, nodes)
	if err != nil {
		return err
	}
	fmt.Println("Prove: range evidence produced")

	// 3. Verify: check the original Root and byte interval without node lookup.
	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	if err != nil {
		return err
	}
	if ok, err := verifier.VerifyRange(root, start, &end, result); err != nil || !ok {
		return fmt.Errorf("range verification: valid=%t, error=%v", ok, err)
	}
	fmt.Println("Verify: range evidence valid")

	// Verification authenticates metadata and the ordered segment CIDs. Fetching,
	// hashing, checking lengths, and assembling their bytes belong to the client.
	// This tiny map stands in for untrusted content storage in the example.
	meta := result.Metadata
	firstIndex := start / meta.ChunkSize
	var assembled []byte
	for offset, segment := range result.Segments {
		body, found := payloads[segment.Target.String()]
		if !found {
			return fmt.Errorf("segment payload is unavailable")
		}
		actual, err := segment.Target.Prefix().Sum(body)
		if err != nil {
			return err
		}
		if !actual.Equals(segment.Target) {
			return fmt.Errorf("segment payload does not match authenticated CID")
		}
		index := firstIndex + uint64(offset)
		expectedSize := min(meta.ChunkSize, meta.TotalSize-index*meta.ChunkSize)
		if uint64(len(body)) != expectedSize {
			return fmt.Errorf("segment length does not match authenticated geometry")
		}
		assembled = append(assembled, body...)
	}
	firstByte := firstIndex * meta.ChunkSize
	selected := assembled[start-firstByte : end-firstByte]
	if string(selected) != "lo wor" {
		return fmt.Errorf("unexpected range bytes: %q", selected)
	}
	fmt.Println("Direct index labels: 0, 1, 2 (eight-byte big-endian)")
	fmt.Println("Range proof and all segment CIDs verified")
	fmt.Printf("Bytes [%d,%d): %s\n", start, end, selected)
	return nil
}
