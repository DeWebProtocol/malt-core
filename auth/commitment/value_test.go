package commitment_test

import (
	"bytes"
	"testing"

	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
)

func TestValueBindsProfileAndDetachesBytes(t *testing.T) {
	for _, profile := range []maltcid.ProfileID{maltcid.KZG4096, maltcid.IPA256} {
		parameters, err := maltcid.Profile(profile)
		if err != nil {
			t.Fatal(err)
		}
		raw := bytes.Repeat([]byte{7}, parameters.CommitmentSize)
		value, err := commitment.NewValue(profile, raw)
		if err != nil {
			t.Fatal(err)
		}
		raw[0]++
		encoded := value.Bytes()
		parsed, err := commitment.ParseValue(encoded)
		if err != nil || !parsed.Equals(value) || parsed.ProfileID() != profile {
			t.Fatalf("roundtrip: %v", err)
		}
		encoded[len(encoded)-1]++
		data, err := value.CommitmentBytes(profile)
		if err != nil || !bytes.Equal(data, bytes.Repeat([]byte{7}, len(raw))) {
			t.Fatalf("caller mutated commitment: %v", err)
		}
		data[0]++
		again, _ := value.CommitmentBytes(profile)
		if again[0] != 7 {
			t.Fatal("CommitmentBytes returned an alias")
		}
		other := maltcid.IPA256
		if profile == other {
			other = maltcid.KZG4096
		}
		if _, err := value.CommitmentBytes(other); err == nil {
			t.Fatal("accepted a different cryptographic profile")
		}
		if _, err := commitment.NewValue(profile, raw[:len(raw)-1]); err == nil {
			t.Fatal("accepted the wrong commitment width")
		}
		root, err := maltcid.NewRoot(maltcid.RootDescriptor{Layout: maltcid.Prefix, InputRule: 1, Profile: profile}, again)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := commitment.ParseValue(root.Bytes()); err == nil {
			t.Fatal("a semantic Root was accepted as a primitive commitment")
		}
	}
	if (commitment.Value{}).Defined() {
		t.Fatal("zero commitment is defined")
	}
	if _, err := (commitment.Value{}).CommitmentBytes(maltcid.IPA256); err == nil {
		t.Fatal("undefined commitment supplied bytes")
	}
}
