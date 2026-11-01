# Third-party notices

## Kiosk Satellite plugin template

`sdk/`, `tools/` and `.github/workflows/build.yml` come from the Kiosk Satellite plugin template
(https://github.com/jxlarrea/kiosk-satellite-plugins) under the Apache License 2.0, included as
`LICENSE-SDK`. `tools/test.py` was changed to run this plugin's tests, and `tools/check-sdk.py` to compare `LICENSE-SDK`.

## TECHO5

The handshake in `Sealed.java` follows TECHO5's `echod/internal/lib/sealed/sealed.go`
(https://github.com/HuskerMinion/techo5), MIT License, Copyright (c) 2026 TECHO5 contributors.

## TweetNaCl

The X25519 code in `Crypto.java` follows TweetNaCl (https://tweetnacl.cr.yp.to), which is in the
public domain.
