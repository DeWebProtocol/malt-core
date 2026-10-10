// Command range authenticates a fixed-chunk byte range and checks its payload.
package main

import (
	"context"
	"encoding/json"
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
	// block may be shorter. The application owns and validates byte geometry.
	chunks := [][]byte{[]byte("hell"), []byte("o wo"), []byte("rld")}
	payloads := make(map[string][]byte)
	state := engine.State{
		Descriptor: maltcid.RootDescriptor{
			Layout: maltcid.Positional, DerivationProfile: uint8(derivation.Direct), Profile: maltcid.IPA256,
		},
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
	// Application metadata is an ordinary content-addressed JSON document.
	geometry := struct {
		ChunkSize uint64 `json:"chunk_size,string"`
		TotalSize uint64 `json:"total_size,string"`
	}{4, 11}
	metadata, err := json.Marshal(geometry)
	if err != nil {
		return err
	}
	state.PayloadCID, err = (cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}).Sum(metadata)
	if err != nil {
		return err
	}
	payloads[state.PayloadCID.String()] = metadata
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

	// 2. Translate the application byte interval to Core element indices.
	start, end := uint64(3), uint64(9)
	firstIndex, stopIndex := start/geometry.ChunkSize, (end-1)/geometry.ChunkSize+1
	result, err := prover.ProveRange(ctx, root, firstIndex, &stopIndex, nodes)
	if err != nil {
		return err
	}
	fmt.Println("Prove: range evidence produced")

	// 3. Verify the selected Root and index interval without node lookup.
	verifier, err := builtin.NewVerifier(maltcid.IPA256)
	if err != nil {
		return err
	}
	if ok, err := verifier.VerifyRange(root, firstIndex, &stopIndex, result); err != nil || !ok {
		return fmt.Errorf("range verification: valid=%t, error=%v", ok, err)
	}
	fmt.Println("Verify: range evidence valid")

	// Verification authenticates metadata and the ordered segment CIDs. Fetching,
	// hashing, checking lengths, and assembling their bytes belong to the client.
	// This tiny map stands in for untrusted content storage in the example.
	bound := payloads[result.Metadata.PayloadCID.String()]
	actual, err := result.Metadata.PayloadCID.Prefix().Sum(bound)
	if err != nil || !actual.Equals(result.Metadata.PayloadCID) {
		return fmt.Errorf("metadata CID mismatch")
	}
	if err = json.Unmarshal(bound, &geometry); err != nil {
		return err
	}
	if geometry.ChunkSize == 0 || geometry.TotalSize == 0 || (geometry.TotalSize-1)/geometry.ChunkSize+1 != result.Metadata.Count {
		return fmt.Errorf("invalid file geometry")
	}
	if start/geometry.ChunkSize != firstIndex || (end-1)/geometry.ChunkSize+1 != stopIndex {
		return fmt.Errorf("range translation mismatch")
	}
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
		expectedSize := min(geometry.ChunkSize, geometry.TotalSize-index*geometry.ChunkSize)
		if uint64(len(body)) != expectedSize {
			return fmt.Errorf("segment length does not match authenticated geometry")
		}
		assembled = append(assembled, body...)
	}
	firstByte := firstIndex * geometry.ChunkSize
	selected := assembled[start-firstByte : end-firstByte]
	if string(selected) != "lo wor" {
		return fmt.Errorf("unexpected range bytes: %q", selected)
	}
	fmt.Println("Direct index labels: 0, 1, 2 (eight-byte big-endian)")
	fmt.Println("Range proof and all segment CIDs verified")
	fmt.Printf("Bytes [%d,%d): %s\n", start, end, selected)
	return nil
}
