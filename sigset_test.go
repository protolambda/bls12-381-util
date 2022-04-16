package blsu

import (
	"crypto/rand"
	"fmt"
	kbls "github.com/kilic/bls12-381"
	"testing"
)

func randSK(t testing.TB) *SecretKey {
	var sk SecretKey
	_, err := (*kbls.Fr)(&sk).Rand(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &sk
}

func prepareSignatureSetTest(t testing.TB, n int) ([]*Pubkey, [][]byte, []*Signature) {
	pubs := make([]*Pubkey, n, n)
	msgs := make([][]byte, n, n)
	sigs := make([]*Signature, n, n)
	for i := 0; i < n; i++ {
		sk := randSK(t)
		pub, err := SkToPk(sk)
		if err != nil {
			t.Fatal(err)
		}
		var msg [32]byte
		msg[0] = 0
		rand.Read(msg[:])
		sig := Sign(sk, msg[:])
		pubs[i] = pub
		msgs[i] = msg[:]
		sigs[i] = sig
	}
	return pubs, msgs, sigs
}

func TestSignatureSetVerifyRandom(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 10, 42, 100, 101} {
		t.Run(fmt.Sprintf("SignatureSet_%d", n), func(t *testing.T) {
			pubs, msgs, sigs := prepareSignatureSetTest(t, n)
			valid, err := SignatureSetVerify(pubs, msgs, sigs)
			if err != nil {
				t.Fatal(err)
			}
			if !valid {
				t.Fatalf("expected set to be valid")
			}
		})
	}
}

type batchVerifyTestCase struct {
	Input struct {
		Pubkey    []hexStr48 `json:"pubkeys"`
		Message   []hexStr   `json:"messages"`
		Signature []hexStr96 `json:"signatures"`
	} `json:"input"`
	Output bool `json:"output"`
}

func TestSignatureSetVerify(t *testing.T) {
	runTestCases(t, "batch_verify", func(t *testing.T, getData func(interface{})) {
		var data batchVerifyTestCase
		getData(&data)

		var pubs []*Pubkey
		var msgs [][]byte
		var sigs []*Signature

		for _, pubRaw := range data.Input.Pubkey {
			var pub Pubkey
			if err := pub.Deserialize((*[48]byte)(&pubRaw)); err != nil {
				if data.Output {
					t.Fatalf("expected valid batch verify, but got invalid pubkey %x: %v", pubRaw[:], err)
				} else {
					// expected
					return
				}
			}
			pubs = append(pubs, &pub)
		}
		for _, sigRaw := range data.Input.Signature {
			var sig Signature
			if err := sig.Deserialize((*[96]byte)(&sigRaw)); err != nil {
				if data.Output {
					t.Fatalf("expected valid batch verify, but got invalid signature %x: %v", sigRaw[:], err)
				} else {
					// expected
					return
				}
			}
			sigs = append(sigs, &sig)
		}
		for _, msgRaw := range data.Input.Message {
			msgs = append(msgs, msgRaw)
		}

		ok, err := SignatureSetVerify(pubs, msgs, sigs)
		if err != nil {
			t.Fatal("usage error")
		}
		if ok {
			if data.Output {
				// expected
				return
			} else {
				t.Fatal("expected invalid batch verify, but accepted batch")
			}
		} else {
			if data.Output {
				t.Fatal("failed to batch verify, but expected valid batch")
			} else {
				// expected
				return
			}
		}
	})
}
