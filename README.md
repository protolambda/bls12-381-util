# BLS 12-381 util

BLS 12-381 util (BLSU, "bless you") is a collection of utils to work with BLS 12-381 in Go.

*Warning: these wrapper utils have not been audited.*

This package wraps [`github.com/kilic/bls12-381`](https://github.com/kilic/bls12-381), 
a pure Go implementation of BLS, no CGO involved, no special dependencies. ([audit info](https://github.com/kilic/bls12-381/issues/19))

## Utils

- Eth2 Typing
  - Pubkeys: `PointG1` wrapper
  - Signatures: `PointG2` wrapper
  - Secret keys: `Fr` wrapper
  - Signatures sets: see below
- [Draft 4](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04) for signatures
  - Hash to curve, from `kilic/bls12-381`: `BLS12381G1_XMD:SHA-
    256_SSWU_RO_`, `BLS12381G2_XMD:SHA-256_SSWU_RO_`
  - Schemes:
    - Core operations:
      - `KeyGen`
      - `SkToPk`
      - ~~`KeyValidate`~~, implemented as part of Pubkey deserialization
      - `CoreSign`
      - `CoreVerify`
      - `Aggregate`
      - `CoreAggregateVerify`
    - ~~Basic scheme~~, not supported
    - ~~Message Augmentation scheme~~, not supported
    - `POP`, Proof of Possession scheme (used in Eth2):
      - ~~PopProve~~, not supported, assumed through application-specific implementation
      - ~~PopVerify~~, not supported, assumed through application-specific implementation
      - `FastAggregateVerify`
- Eth2 additions
  - [`eth2_aggregate_pubkeys`](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/altair/bls.md#eth2_aggregate_pubkeys)
  - [`eth2_fast_aggregate_verify`](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/altair/bls.md#eth2_fast_aggregate_verify)
- [Signature sets](https://ethresear.ch/t/fast-verification-of-multiple-bls-signatures/5407) (verify non-singular set of signatures and its respective pubkeys and messages)

## Testing

- TODO: Unit tests
- TODO: Eth2 BLS tests
- TODO: Eth2 spec tests
- TODO: standard tests (if any)

## License

MIT, see [`LICENSE`](./LICENSE) file.
