package blsu

import (
	kbls "github.com/kilic/bls12-381"
	"testing"
)

type deferBLSType struct {
	name   string
	create func() DeferBLS
}

var deferBLSTypes = []deferBLSType{
	{"aggregate", NewAggregateCheck},
	{"immediate", func() DeferBLS { return ImmediateCheck{} }},
}

func TestDeferBLSVerify(t *testing.T) {
	runTestCases(t, "verify", func(t *testing.T, getData func(interface{})) {
		var data verifyTestCase
		getData(&data)
		var pub Pubkey
		if err := pub.Deserialize((*[48]byte)(&data.Input.Pubkey)); err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure, failed to deserialize pubkey (%x): %v", data.Input.Pubkey[:], err)
			}
		}
		var sig Signature
		if err := sig.Deserialize((*[96]byte)(&data.Input.Signature)); err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure, failed to deserialize signature (%x): %v", data.Input.Signature[:], err)
			}
		}

		for _, typ := range deferBLSTypes {
			t.Run(typ.name, func(t *testing.T) {
				deferBLS := typ.create()
				err := deferBLS.Verify(&pub, data.Input.Message[:], &sig)
				if err == nil {
					err = deferBLS.Check()
				}
				if (err == nil) != data.Output {
					t.Fatalf("expected different output, got %v, expected %v", err == nil, data.Output)
				}
			})
		}
	})
}

func TestDeferBLSAggregateVerify(t *testing.T) {
	runTestCases(t, "aggregate_verify", func(t *testing.T, getData func(interface{})) {
		var data aggregateVerifyTestCase
		getData(&data)
		pubkeys, err := parsePubkeys(data.Input.Pubkeys)
		if err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure: %v", err)
			}
		}
		messages := make([][]byte, len(data.Input.Messages), len(data.Input.Messages))
		for i := range data.Input.Messages {
			messages[i] = data.Input.Messages[i][:]
		}
		// Our signature Deserialization cannot deserialize anything else than 96 bytes, yay typing.
		// But the tests have invalid-signature cases for non-96 bytes, catch those.
		var sigData [96]byte
		if len(data.Input.Signature) != 96 {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("expected 96 byte signature, got %d bytes: %x", len(data.Input.Signature), data.Input.Signature[:])
			}
		} else {
			copy(sigData[:], data.Input.Signature)
		}
		var sig Signature
		if err := sig.Deserialize(&sigData); err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure, failed to deserialize signature (%x): %v", data.Input.Signature[:], err)
			}
		}

		for _, typ := range deferBLSTypes {
			t.Run(typ.name, func(t *testing.T) {
				deferBLS := typ.create()
				err := deferBLS.AggregateVerify(pubkeys, messages, &sig)
				if err == nil {
					err = deferBLS.Check()
				}
				if (err == nil) != data.Output {
					t.Fatalf("expected different output, got %v, expected %v", err == nil, data.Output)
				}
			})
		}
	})
}

func TestDeferBLSFastAggregateVerify(t *testing.T) {
	runTestCases(t, "fast_aggregate_verify", func(t *testing.T, getData func(interface{})) {
		var data fastAggregateVerifyTestCase
		getData(&data)
		pubkeys, err := parsePubkeys(data.Input.Pubkeys)
		if err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure: %v", err)
			}
		}
		message := data.Input.Message[:]
		var sig Signature
		if err := sig.Deserialize((*[96]byte)(&data.Input.Signature)); err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure, failed to deserialize signature (%x): %v", data.Input.Signature[:], err)
			}
		}

		for _, typ := range deferBLSTypes {
			t.Run(typ.name, func(t *testing.T) {
				deferBLS := typ.create()
				err := deferBLS.FastAggregateVerify(pubkeys, message, &sig)
				if err == nil {
					err = deferBLS.Check()
				}
				if (err == nil) != data.Output {
					t.Fatalf("expected different output, got %v, expected %v", err == nil, data.Output)
				}
			})
		}
	})
}

func TestDeferEth2FastAggregateVerify(t *testing.T) {
	// behaves the same as FastAggregateVerify otherwise
	runTestCases(t, "fast_aggregate_verify", func(t *testing.T, getData func(interface{})) {
		var data fastAggregateVerifyTestCase
		getData(&data)
		pubkeys, err := parsePubkeys(data.Input.Pubkeys)
		if err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure: %v", err)
			}
		}
		message := data.Input.Message[:]
		var sig Signature
		if err := sig.Deserialize((*[96]byte)(&data.Input.Signature)); err != nil {
			if !data.Output {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure, failed to deserialize signature (%x): %v", data.Input.Signature[:], err)
			}
		}
		// Override test result where Eth2FastAggregateVerify is supposed to be different than FastAggregateVerify
		if len(pubkeys) == 0 && kbls.NewG2().IsZero((*kbls.PointG2)(&sig)) {
			data.Output = true
		}
		for _, typ := range deferBLSTypes {
			t.Run(typ.name, func(t *testing.T) {
				deferBLS := typ.create()
				err := deferBLS.Eth2FastAggregateVerify(pubkeys, message, &sig)
				if err == nil {
					err = deferBLS.Check()
				}
				if (err == nil) != data.Output {
					t.Fatalf("expected different output, got %v, expected %v", err == nil, data.Output)
				}
			})
		}
	})
}
