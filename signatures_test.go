package blsu

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	kbls "github.com/kilic/bls12-381"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hashToG2TestCase struct {
	Input struct {
		Msg string `json:"msg"`
	} `json:"input"`
	Output struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"output"`
}

const fpByteSize = 48

func TestHashToG2(t *testing.T) {
	runTestCases(t, "hash_to_G2", func(t *testing.T, getData func(interface{})) {
		var data hashToG2TestCase
		getData(&data)
		g2 := kbls.NewG2()
		dom := []byte("QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_")
		out, err := g2.HashToCurve([]byte(data.Input.Msg), dom)
		if err != nil {
			t.Fatal(err)
		}
		g2.Affine(out)
		uncompressed := g2.ToUncompressed(out)
		x := strings.Split(data.Output.X, ",")
		y := strings.Split(data.Output.Y, ",")
		must := func(err error) {
			if err != nil {
				t.Fatal(err)
			}
		}
		var x1, x2, y1, y2 hexStr
		must(x1.UnmarshalText([]byte(x[0])))
		must(x2.UnmarshalText([]byte(x[1])))
		must(y1.UnmarshalText([]byte(y[0])))
		must(y2.UnmarshalText([]byte(y[1])))

		if !bytes.Equal(uncompressed[:fpByteSize], x2) {
			t.Errorf("X1: got %x but expected %x", uncompressed[:fpByteSize], x2)
		}
		if !bytes.Equal(uncompressed[fpByteSize:fpByteSize*2], x1) {
			t.Errorf("X2: got %x but expected %x", uncompressed[fpByteSize:fpByteSize*2], x1)
		}

		if !bytes.Equal(uncompressed[fpByteSize*2:fpByteSize*3], y2) {
			t.Errorf("Y1: got %x but expected %x", uncompressed[fpByteSize*2:fpByteSize*3], y2)
		}
		if !bytes.Equal(uncompressed[fpByteSize*3:], y1) {
			t.Errorf("Y2: got %x but expected %x", uncompressed[fpByteSize*3:], y1)
		}
	})
}

func TestSecretKey_Deserialize(t *testing.T) {
	// TODO TestSecretKey_Deserialize
}

func TestSecretKey_Serialize(t *testing.T) {
	// TODO TestSecretKey_Serialize
}

type deserializationG1TestCase struct {
	Input struct {
		Pubkey hexStr `json:"pubkey"`
	} `json:"input"`
	Output bool `json:"output"`
}

func TestPubkey_Deserialize(t *testing.T) {
	runTestCases(t, "deserialization_G1", func(t *testing.T, getData func(interface{})) {
		var data deserializationG1TestCase
		getData(&data)
		// length is included in typing here, just invalid input
		if len(data.Input.Pubkey) != 48 {
			return
		}
		var pubRaw [48]byte
		copy(pubRaw[:], data.Input.Pubkey)
		var pub Pubkey
		err := pub.Deserialize(&pubRaw)
		if err != nil {
			if data.Output {
				t.Fatalf("unexpected deserialization error: %v", err)
			} else {
				// expected
				return
			}
		} else {
			if data.Output {
				// expected success. Now try serialize it back
				t.Run("serialize", func(t *testing.T) {
					out := pub.Serialize()
					if !bytes.Equal(out[:], data.Input.Pubkey) {
						t.Fatalf("expected different serialized result:\n%x\n%x", out[:], data.Input.Pubkey)
					}
				})
			} else {
				t.Fatalf("expected deserialization to fail, but got: %v", &pub)
			}
		}
	})
}

type deserializationG2TestCase struct {
	Input struct {
		Signature hexStr `json:"signature"`
	} `json:"input"`
	Output bool `json:"output"`
}

func TestSignature_Deserialize(t *testing.T) {
	runTestCases(t, "deserialization_G2", func(t *testing.T, getData func(interface{})) {
		var data deserializationG2TestCase
		getData(&data)
		// length is included in typing here, just invalid input
		if len(data.Input.Signature) != 96 {
			return
		}
		var sigRaw [96]byte
		copy(sigRaw[:], data.Input.Signature)
		var sig Signature
		err := sig.Deserialize(&sigRaw)
		if err != nil {
			if data.Output {
				t.Fatalf("unexpected deserialization error: %v", err)
			} else {
				// expected
				return
			}
		} else {
			if data.Output {
				// expected success. Now try serialize it back
				t.Run("serialize", func(t *testing.T) {
					out := sig.Serialize()
					if !bytes.Equal(out[:], data.Input.Signature) {
						t.Fatalf("expected different serialized result:\n%x\n%x", out[:], data.Input.Signature)
					}
				})
			} else {
				t.Fatalf("expected deserialization to fail, but got: %v", &sig)
			}
		}
	})
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

type signTestCase struct {
	Input struct {
		Privkey hexStr32 `json:"privkey"`
		Message hexStr   `json:"message"`
	}
	Output hexStr `json:"output"`
}

func TestSign(t *testing.T) {
	runTestCases(t, "sign", func(t *testing.T, getData func(interface{})) {
		var data signTestCase
		getData(&data)
		var sk SecretKey
		if err := sk.Deserialize((*[32]byte)(&data.Input.Privkey)); err != nil {
			if len(data.Output) != 0 {
				t.Fatalf("unexpected failure: %v", err)
			}
			return
		} else {
			if len(data.Output) == 0 {
				t.Fatalf("expected failure, but did not")
			}
		}
		sig := Sign(&sk, data.Input.Message)
		res := sig.Serialize()
		if !bytes.Equal(res[:], data.Output) {
			t.Fatalf("got %x, expected %x", res, data.Output)
		}
	})
}

type aggregateTestCase struct {
	Input  []hexStr96 `json:"input"`
	Output *hexStr96  `json:"output"`
}

func TestAggregate(t *testing.T) {
	runTestCases(t, "aggregate", func(t *testing.T, getData func(interface{})) {
		var data aggregateTestCase
		getData(&data)
		inputs := make([]*Signature, len(data.Input), len(data.Input))
		for i, sig := range data.Input {
			inputs[i] = new(Signature)
			if err := inputs[i].Deserialize((*[96]byte)(&sig)); err != nil {
				if data.Output == nil {
					// expected failure
					return
				} else {
					t.Fatalf("unexpected failure, failed to deserialize signature %d (%x): %v", i, sig[:], err)
				}
			}
		}
		out, err := Aggregate(inputs)
		if err != nil {
			if data.Output == nil {
				// expected failure
				return
			} else {
				t.Fatalf("unexpected failure, failed to aggregate signatures: %v", err)
			}
		} else {
			res := out.Serialize()
			if !bytes.Equal(res[:], data.Output[:]) {
				t.Fatalf("got %x, expected %x", res[:], data.Output[:])
			}
		}
	})
}

func TestAggregatePubkeys(t *testing.T) {
	// TODO TestAggregatePubkeys
}

type verifyTestCase struct {
	Input struct {
		Pubkey    hexStr48 `json:"pubkey"`
		Message   hexStr32 `json:"message"`
		Signature hexStr96 `json:"signature"` // the signature to verify against pubkey and message
	}
	Output bool `json:"output"` // VALID or INVALID
}

func TestVerify(t *testing.T) {
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
		res := Verify(&pub, data.Input.Message[:], &sig)
		if res != data.Output {
			t.Fatalf("expected different output, got %v, expected %v", res, data.Output)
		}
	})
}

type aggregateVerifyTestCase struct {
	Input struct {
		Pubkeys   []hexStr48 `json:"pubkeys"`
		Messages  []hexStr32 `json:"messages"`
		Signature hexStr     `json:"signature"`
	}
	Output bool `json:"output"` // VALID or INVALID
}

func parsePubkeys(input []hexStr48) (pubkeys []*Pubkey, err error) {
	pubkeys = make([]*Pubkey, len(input), len(input))
	for i, pub := range input {
		pubkeys[i] = new(Pubkey)
		if err := pubkeys[i].Deserialize((*[48]byte)(&pub)); err != nil {
			return nil, fmt.Errorf("failed to deserialize pubkey %d (%x): %v", i, pub[:], err)
		}
	}
	return pubkeys, nil
}

func TestAggregateVerify(t *testing.T) {
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
		res := AggregateVerify(pubkeys, messages, &sig)
		if res != data.Output {
			t.Fatalf("expected different output, got %v, expected %v", res, data.Output)
		}
	})
}

type fastAggregateVerifyTestCase struct {
	Input struct {
		Pubkeys   []hexStr48 `json:"pubkeys"`
		Message   hexStr32   `json:"message"`
		Signature hexStr96   `json:"signature"`
	}
	Output bool `json:"output"` // VALID or INVALID
}

func TestFastAggregateVerify(t *testing.T) {
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
		res := FastAggregateVerify(pubkeys, message, &sig)
		if res != data.Output {
			t.Fatalf("expected different output, got %v, expected %v", res, data.Output)
		}
	})
}

func TestEth2FastAggregateVerify(t *testing.T) {
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
		res := Eth2FastAggregateVerify(pubkeys, message, &sig)
		if res != data.Output {
			t.Fatalf("expected different output, got %v, expected %v", res, data.Output)
		}
	})
}

type hexStr []byte

func (v *hexStr) UnmarshalText(text []byte) error {
	if len(text) >= 2 && text[0] == '0' && text[1] == 'x' {
		text = text[2:]
	}
	l := hex.DecodedLen(len(text))
	dat := make([]byte, l, l)
	_, err := hex.Decode(dat, text)
	*v = dat
	return err
}

func unmarshalHex(dst []byte, text []byte) error {
	if len(text) >= 2 && text[0] == '0' && text[1] == 'x' {
		text = text[2:]
	}
	l := hex.DecodedLen(len(text))
	if l != len(dst) {
		return fmt.Errorf("unexpected length, not %d bytes: %d", len(dst), l)
	}
	_, err := hex.Decode(dst, text)
	return err
}

type hexStr32 [32]byte

func (v *hexStr32) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return nil
	}
	return unmarshalHex(v[:], text)
}

type hexStr48 [48]byte

func (v *hexStr48) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return nil
	}
	return unmarshalHex(v[:], text)
}

type hexStr96 [96]byte

func (v *hexStr96) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		return nil
	}
	return unmarshalHex(v[:], text)
}

var testDir = "./test-vectors"

func runTestCases(t *testing.T, path string, runCase func(t *testing.T, getData func(interface{}))) {
	t.Run(path, func(t *testing.T) {
		casesPath := filepath.Join(testDir, path)
		casesDir := os.DirFS(casesPath)
		fs.WalkDir(casesDir, ".", func(path string, d fs.DirEntry, err error) error {
			// recurse into main dir
			if path == "." {
				return nil
			}
			// a dir? exit with warning
			if d.IsDir() {
				return fmt.Errorf("unexpected dir: path: %q, name: %q", path, d.Name())
			}
			// can't open the file? skip it
			if err != nil {
				return nil
			}
			// each file is a test-case
			name := d.Name()
			name = name[:len(name)-len(filepath.Ext(name))] // strip extension for pretty test name
			t.Run(name, func(t *testing.T) {
				// run call-back to process test-case
				runCase(t, func(dst interface{}) {
					data, err := fs.ReadFile(casesDir, path)
					if err != nil {
						t.Fatalf("failed to read %q: %v", path, err)
						return
					}
					if err := json.Unmarshal(data, dst); err != nil {
						t.Fatalf("failed to decode %q: %v", path, err)
						return
					}
				})
			})
			// keep going through other files in this dir.
			return nil
		})
	})
}
