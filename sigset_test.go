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

func TestSignatureSetVerify(t *testing.T) {
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
