# FROST

This implementation was part of the contribution for the following paper:

Chelsea Komlo, Ian Goldberg.
["FROST: Flexible Round-Optimized Schnorr Threshold SIgnatures."](https://eprint.iacr.org/2020/852.pdf
) Conference on Selected Areas in Cryptography, 2020.

This library provides the ability for participants to perform key generation
either via a trusted dealer or via a distributed key generation stage as
defined in the FROST KeyGen protocol. This library also provides the ability to
perform threshold signing operations and verification of signatures.

## Use

Note that this library does not provide support for serialization and
deserialization of data. Further, implementations should perform higher-level
authentication steps between participants.

## Development

Development on this project is frozen and will not implement any additional features.
Forking this project to extend features is welcome.

Running tests for this project is standard to any Cargo library. To run tests,
run:

```
cargo test
```

from the top-level directory of the repository.
