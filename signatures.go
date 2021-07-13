package blsu

import (
	"errors"
	"fmt"

	kbls "github.com/kilic/bls12-381"
)

// IETF signature draft v4:
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04
//

var domain = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

// cipher-suite: BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_
// BLS_SIG_
// BLS12381G2_XMD:SHA-256_SSWU_RO  # hash to curve suite
// _
// POP  # proof-of-possession scheme
// _

// *  hash_to_point: a hash from arbitrary strings to elliptic curve
// points. hash_to_point MUST be defined in terms of a hash-to-curve
// suite [I-D.irtf-cfrg-hash-to-curve].
//
// The RECOMMENDED hash-to-curve domain separation tag is the
// ciphersuite ID string defined above.
//
// *  hash_pubkey_to_point (only specified when SC is proof-of-
// possession): a hash from serialized public keys to elliptic curve
// points. hash_pubkey_to_point MUST be defined in terms of a hash-
// to-curve suite [I-D.irtf-cfrg-hash-to-curve].
//
// The hash-to-curve domain separation tag MUST be distinct from the
// domain separation tag used for hash_to_point.  It is RECOMMENDED
// that the domain separation tag be constructed similarly to the
// ciphersuite ID string, namely:
// "BLS_POP_" || H2C_SUITE_ID || SC_TAG || "_"

type Pubkey kbls.PointG1

// Serialize to compressed point
func (pub *Pubkey) Serialize() (out [48]byte) {
	// TODO: in Go 1.17 this copy can be avoided with a slice->array cast
	copy(out[:], kbls.NewG1().ToCompressed((*kbls.PointG1)(pub)))
	return
}

// Deserialize compressed point
func (pub *Pubkey) Deserialize(in *[48]byte) error {
	// includes sub-group check
	p, err := kbls.NewG1().FromCompressed(in[:])
	if err != nil {
		return err
	}
	*pub = (Pubkey)(*p)
	return nil
}

type Signature kbls.PointG2

// Serialize to compressed point
func (sig *Signature) Serialize() (out [96]byte) {
	// TODO: in Go 1.17 this copy can be avoided with a slice->array cast
	copy(out[:], kbls.NewG2().ToCompressed((*kbls.PointG2)(sig)))
	return
}

// Deserialize compressed point
func (sig *Signature) Deserialize(in *[96]byte) error {
	// includes sub-group check
	p, err := kbls.NewG2().FromCompressed(in[:])
	if err != nil {
		return err
	}
	*sig = (Signature)(*p)
	return nil
}

type SecretKey kbls.Fr

// Serialize to big-endian serialized integer
func (sk *SecretKey) Serialize() (out [32]byte) {
	// ToBytes output is always 32 bytes, no need for extra padding or alignment work
	copy(out[:], ((*kbls.Fr)(sk)).ToBytes())
	return
}

// Deserialize big-endian serialized integer. A modulo r is applied to out-of-range keys.
func (sk *SecretKey) Deserialize(in *[32]byte) {
	(*kbls.Fr)(sk).FromBytes(in[:])
}

// The SkToPk algorithm takes a secret key SK and outputs the
// corresponding public key PK.  Section 2.3 discusses requirements for SK.
func SkToPk(sk *SecretKey) (*Pubkey, error) {
	// a secret integer such that 1 <= SK < r.
	if ((*kbls.Fr)(sk)).IsZero() {
		return nil, errors.New("secret key may not be zero")
	}

	// 1. xP = SK * P
	// 2. PK = point_to_pubkey(xP)
	// 3. return PK
	return nil, nil
}

// TODO: unsupported, should be part of bytes->Pubkey deserialization
//
//// The KeyValidate algorithm ensures that a public key is valid.  In
//// particular, it ensures that a public key represents a valid, non-
//// identity point that is in the correct subgroup.
//func KeyValidate(pub []byte) bool {
//	// 1. xP = pubkey_to_point(PK)
//	// 2. If xP is INVALID, return INVALID
//	// 3. If xP is the identity element, return INVALID
//	// 4. If pubkey_subgroup_check(xP) is INVALID, return INVALID
//	// 5. return VALID
//	return false
//}

// The CoreSign algorithm computes a signature from SK, a secret key,
//   and message, an octet string.
func CoreSign(sk *SecretKey, message []byte) (*Signature, error) {
	g2 := kbls.NewG2()
	// 1. Q = hash_to_point(message)
	Q, err := g2.HashToCurve(message, domain)
	if err != nil {
		return nil, err
	}
	// 2. R = SK * Q
	var R kbls.PointG2
	g2.MulScalar(&R, Q, (*kbls.Fr)(sk))
	// 3. signature = point_to_signature(R)
	// serialization is deferred, see Signature.Serialize()
	signature := (*Signature)(&R)
	// 4. return signature
	return signature, nil
}

// The CoreVerify algorithm checks that a signature is valid for the
//   octet string message under the public key PK.
func CoreVerify(pk *Pubkey, message []byte, signature *Signature) bool {
	// 1. R = signature_to_point(signature)
	R := (*kbls.PointG2)(signature)
	// 2. If R is INVALID, return INVALID
	// 3. If signature_subgroup_check(R) is INVALID, return INVALID
	// 4. If KeyValidate(PK) is INVALID, return INVALID
	// steps 2-4 are part of bytes -> *Signature deserialization

	// 5. xP = pubkey_to_point(PK)
	xP := (*kbls.PointG1)(pk)
	// 6. Q = hash_to_point(message)
	Q, err := kbls.NewG2().HashToCurve(message, domain)
	if err != nil {
		// e.g. when the domain is too long. Maybe change to panic if never due to a usage error?
		return false
	}
	// 7. C1 = pairing(Q, xP)
	eng := kbls.NewEngine()
	eng.AddPair(xP, Q)
	// 8. C2 = pairing(R, P)
	P := &kbls.G1One
	eng.AddPairInv(P, R) // inverse, optimization to mul with inverse and check equality to 1
	// 9. If C1 == C2, return VALID, else return INVALID
	return eng.Check()
}

// The Aggregate algorithm aggregates multiple signatures into one.
func Aggregate(signatures []*Signature) (*Signature, error) {
	// Precondition: n >= 1, otherwise return INVALID.
	if len(signatures) == 0 {
		return nil, fmt.Errorf("need at least 1 signature")
	}

	// 1. aggregate = signature_to_point(signature_1)
	// make a copy of the first signature
	aggregate := (kbls.PointG2)(*signatures[0])
	// 2. If aggregate is INVALID, return INVALID
	// part of the Signature deserialization

	g2 := kbls.NewG2()
	// 3. for i in 2, ..., n:
	for i := 1; i < len(signatures); i++ {
		// 4. next = signature_to_point(signature_i)
		next := (*kbls.PointG2)(signatures[i])
		// 5. If next is INVALID, return INVALID
		// part of the Signature deserialization
		// 6. aggregate = aggregate + next
		g2.Add(&aggregate, &aggregate, next)
	}
	// 7. signature = point_to_signature(aggregate)
	signature := (*Signature)(&aggregate)
	// 8. return signature
	return signature, nil
}

// The CoreAggregateVerify algorithm checks an aggregated signature over
//   several (PK, message) pairs.
func CoreAggregateVerify(pubkeys []*Pubkey, messages [][]byte, signature *Signature) (bool, error) {
	// Precondition: n >= 1, otherwise return INVALID.

	// 1.  R = signature_to_point(signature)
	// 2.  If R is INVALID, return INVALID
	// 3.  If signature_subgroup_check(R) is INVALID, return INVALID
	// 4.  C1 = 1 (the identity element in GT)
	// 5.  for i in 1, ..., n:
	// 6.      If KeyValidate(PK_i) is INVALID, return INVALID
	// 7.      xP = pubkey_to_point(PK_i)
	// 8.      Q = hash_to_point(message_i)
	// 9.      C1 = C1 * pairing(Q, xP)
	// 10. C2 = pairing(R, P)
	// 11. If C1 == C2, return VALID, else return INVALID
	return false, nil
}

// basic scheme:
//
// This function first ensures that all messages are distinct, and then
// invokes CoreAggregateVerify.
func AggregateVerify(pubkeys []*Pubkey, messages [][]byte, signature *Signature) bool {
	// Precondition: n >= 1, otherwise return INVALID.

	// 1. If any two input messages are equal, return INVALID.
	// 2. return CoreAggregateVerify((PK_1, ..., PK_n),
	//                               (message_1, ..., message_n),
	//                               signature)
	return false
}

// FastAggregateVerify, assuming proof of possession scheme.
//
// a verification algorithm for the aggregate of multiple signatures on the same message.
// This function is faster than AggregateVerify.
func FastAggregateVerify(pubkeys []*Pubkey, message []byte, signature *Signature) bool {
	// Precondition: n >= 1, otherwise return INVALID.

	// Procedure:
	// 1. aggregate = pubkey_to_point(PK_1)
	// 2. for i in 2, ..., n:
	// 3.     next = pubkey_to_point(PK_i)
	// 4.     aggregate = aggregate + next
	// 5. PK = point_to_pubkey(aggregate)
	// 6. return CoreVerify(PK, message, signature)
	return false
}
