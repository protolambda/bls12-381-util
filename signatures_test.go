package blsu

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestSecretKey_Deserialize(t *testing.T) {
	// TODO
}

func TestSecretKey_Serialize(t *testing.T) {
	// TODO
}

func TestPubkey_Deserialize(t *testing.T) {
	// TODO
}

func TestPubkey_Serialize(t *testing.T) {
	// TODO
}

func TestSignature_Deserialize(t *testing.T) {
	// TODO
}

func TestSignature_Serialize(t *testing.T) {
	// TODO
}

func hex32(v string) (out [32]byte) {
	s, err := hex.DecodeString(v)
	if err != nil {
		panic(err)
	}
	if len(s) != 32 {
		panic(fmt.Sprintf("not 32 bytes: %x", s))
	}
	copy(out[:], s)
	return
}

func TestSkToPk(t *testing.T) {
	secret := hex32("263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3")
	var sk SecretKey
	sk.Deserialize(&secret)
	pk, err := SkToPk(&sk)
	if err != nil {
		t.Fatal(err)
	}
	out := pk.Serialize()
	got := hex.EncodeToString(out[:])
	expected := "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
	if got != expected {
		t.Fatalf("expected %s, got pubkey %s", expected, got)
	}
}

func TestSign(t *testing.T) {
	// TODO
}

func TestAggregate(t *testing.T) {
	// TODO
}

func TestAggregatePubkeys(t *testing.T) {
	// TODO
}

func TestVerify(t *testing.T) {
	// TODO
}

func TestAggregateVerify(t *testing.T) {
	// TODO
}

func TestFastAggregateVerify(t *testing.T) {
	// TODO
}

func TestEth2FastAggregateVerify(t *testing.T) {
	// TODO
}

