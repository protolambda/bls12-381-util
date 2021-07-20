package blsu

import (
	"fmt"
	"testing"
)

func BenchmarkSignatureSetVerify(b *testing.B) {
	for _, n := range []int{1, 2, 3, 4, 5, 10, 42, 100, 101} {
		b.Run(fmt.Sprintf("SignatureSet_%d", n), func(b *testing.B) {
			pubs, msgs, sigs := prepareSignatureSetTest(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				valid, err := SignatureSetVerify(pubs, msgs, sigs)
				if err != nil {
					b.Fatal(err)
				}
				if !valid {
					b.Fatalf("expected set to be valid")
				}
			}
		})
	}
}
