# Optional signed certificates

Certificate generation remains unsigned unless the caller explicitly supplies
key material.  The built-in offline signer is HMAC-SHA256 from Python's
standard library, so the locked dependency set does not change.  The signing
surface is an adapter protocol (`CertificateSigner`) and can be replaced by a
separately pinned Ed25519/Sigstore adapter in a deployment that already
provides one.

## CLI

```sh
# Unsigned (the default; no secret is read)
worksonmymachine certify workspace --json

# Explicit opt-in; keep the key in the CI secret store or a protected file
worksonmymachine certify workspace --json \
  --signing-key-file .private/certificate.key \
  --signature-key-id release

worksonmymachine verify-certificate certificate.json \
  --verification-key-file .private/certificate.key
```

The key is used only to calculate/verify the detached signature and is never
included in certificate JSON, API responses, logs, or CLI output.  Verification
returns `invalid` for a tampered payload, wrong key, malformed signature, or
missing key; it never treats an unsigned certificate as valid.

## API

`POST /api/v1/certify` accepts the existing `target` field plus optional
`sign`, `signing_key`, and `signature_key_id` fields.  A request without those
fields produces the legacy unsigned certificate.  `sign=true` requires an
explicit key and returns an additive `signature` object containing only
`algorithm`, `key_id`, and the encoded signature value.

`POST /api/v1/verify-certificate` accepts a certificate and optional
`verification_key`, returning `{signed, valid, algorithm, key_id}` without
returning key material.
