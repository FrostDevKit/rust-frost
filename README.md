# FROST

This implementation was part of the contribution for the following paper:

Chelsea Komlo, Ian Goldberg.
"FROST: Flexible Round-Optimized Schnorr Threshold SIgnatures." Under
submission.

## Use

Note that this library does not provide support for serialization and
deserialization of data, and does not validate whether or not nonces have been
used in previous signing operations. Implementations *must* provide the
capability to guard against nonce-reuse by implementing such checks.

## Development

Development on this project is frozen and will not implement any additional features.
Forking this project to extend features is welcome.

Running tests for this project is standard to any Cargo library. To run tests,
run:

```
cargo test
```

from the top-level directory of the repository.
