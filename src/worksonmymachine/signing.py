"""Optional, offline certificate signing primitives.

The project deliberately keeps signing out of the default audit path.  The
locked runtime does not include a cryptography package, so the built-in signer
uses HMAC-SHA256 from the Python standard library.  ``CertificateSigner`` is a
small protocol so a deployment may provide an Ed25519/Sigstore adapter when a
separately managed, pinned dependency is available without changing the
certificate contract.

Signing keys are accepted only by explicit callers and are never stored on a
certificate.  Verification is deliberately fail-closed: an unsigned,
malformed, or incorrectly keyed certificate returns ``False`` rather than
raising or disclosing key material.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
from typing import Protocol, runtime_checkable

from .models import CertificateSignature, ReproducibilityCertificate


class CertificateSigningError(ValueError):
    """Raised when an explicitly requested signing operation is invalid."""


@runtime_checkable
class CertificateSigner(Protocol):
    """Private-key-agnostic adapter used by certificate signing helpers."""

    algorithm: str
    key_id: str

    def sign(self, payload: bytes) -> str:
        """Return an encoded signature for canonical certificate bytes."""

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify an encoded signature without raising for bad input."""


_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _validate_key_id(value: str) -> str:
    key_id = str(value).strip()
    if not _KEY_ID.fullmatch(key_id):
        raise CertificateSigningError(
            "signature key_id must contain 1-64 letters, numbers, '.', '_' or '-'"
        )
    return key_id


def _key_bytes(value: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(value, str):
        key = value.encode("utf-8")
    else:
        try:
            key = bytes(value)
        except (TypeError, ValueError) as exc:
            raise CertificateSigningError("signing key must be text or bytes") from exc
    if not key:
        raise CertificateSigningError("signing key must not be empty")
    return key


@dataclass(frozen=True, slots=True)
class HMACSHA256Signer:
    """Offline HMAC signer used when no pinned public-key dependency exists."""

    key_id: str = "local"
    _key: bytes = field(repr=False, compare=False, default=b"")
    algorithm: str = field(init=False, default="hmac-sha256")

    def __post_init__(self) -> None:
        object.__setattr__(self, "key_id", _validate_key_id(self.key_id))
        object.__setattr__(self, "_key", _key_bytes(self._key))

    @classmethod
    def from_key(
        cls,
        key: str | bytes | bytearray | memoryview,
        *,
        key_id: str = "local",
    ) -> "HMACSHA256Signer":
        """Build a signer from explicit key material without retaining its repr."""

        return cls(key_id=key_id, _key=_key_bytes(key))

    def sign(self, payload: bytes) -> str:
        digest = hmac.new(self._key, payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a URL-safe base64 signature, returning false for bad input."""

        try:
            encoded = str(signature).encode("ascii")
            encoded += b"=" * (-len(encoded) % 4)
            supplied = base64.b64decode(encoded, altchars=b"-_", validate=True)
        except (TypeError, ValueError, UnicodeError):
            return False
        expected = hmac.new(self._key, payload, hashlib.sha256).digest()
        return hmac.compare_digest(expected, supplied)


# Short alias for callers that prefer the generic HMAC spelling.
HMACSigner = HMACSHA256Signer


def signer_from_key(
    key: str | bytes | bytearray | memoryview,
    *,
    key_id: str = "local",
) -> CertificateSigner:
    """Create the built-in signer from explicitly supplied key material."""

    return HMACSHA256Signer.from_key(key, key_id=key_id)


def canonical_certificate_payload(certificate: ReproducibilityCertificate) -> bytes:
    """Serialize all certificate evidence except its detached signature.

    JSON keys and separators are fixed so another offline implementation can
    independently reproduce the exact bytes.  The signature field is removed
    before signing and verification, preventing a signature from signing
    itself and making tampering detectable.
    """

    payload = certificate.model_dump(mode="json", exclude={"signature"})
    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_certificate(
    certificate: ReproducibilityCertificate,
    *,
    signer: CertificateSigner | None = None,
    signing_key: str | bytes | bytearray | memoryview | None = None,
    key_id: str = "local",
) -> ReproducibilityCertificate:
    """Return a signed copy; no key means the original unsigned copy is kept.

    Passing both a signer and raw key is rejected to avoid ambiguous policy.
    The raw-key convenience path is HMAC-SHA256 and is explicitly opt-in.
    """

    if signer is not None and signing_key is not None:
        raise CertificateSigningError("provide signer or signing_key, not both")
    if signer is None and signing_key is None:
        return certificate
    active = signer or signer_from_key(signing_key, key_id=key_id)
    try:
        algorithm = _validate_key_id(active.algorithm.replace("-", "_"))
        # Keep the wire algorithm name readable while validating only its safe
        # character set.  Custom adapters cannot smuggle arbitrary output into
        # exported certificate metadata.
        algorithm = algorithm.replace("_", "-")
        active_key_id = _validate_key_id(active.key_id)
        signature = active.sign(canonical_certificate_payload(certificate))
    except CertificateSigningError:
        raise
    except Exception as exc:
        raise CertificateSigningError("certificate signing failed") from exc
    if not isinstance(signature, str) or not signature:
        raise CertificateSigningError("certificate signer returned no signature")
    return certificate.model_copy(
        update={
            "signature": CertificateSignature(
                algorithm=algorithm,
                key_id=active_key_id,
                value=signature,
            )
        }
    )


def verify_certificate_signature(
    certificate: ReproducibilityCertificate,
    verification_key: str | bytes | bytearray | memoryview | None = None,
    *,
    signer: CertificateSigner | None = None,
) -> bool:
    """Verify a certificate signature and return ``False`` on every bad input."""

    signature = certificate.signature
    if signature is None:
        return False
    if signer is not None and verification_key is not None:
        return False
    try:
        active = signer
        if active is None:
            if verification_key is None or signature.algorithm != "hmac-sha256":
                return False
            active = signer_from_key(verification_key, key_id=signature.key_id)
        if active.algorithm != signature.algorithm:
            return False
        if active.key_id != signature.key_id:
            return False
        return bool(
            active.verify(canonical_certificate_payload(certificate), signature.value)
        )
    except Exception:
        # Verification is a trust decision, not a parser for untrusted input.
        return False


def certificate_signature_status(
    certificate: ReproducibilityCertificate,
    verification_key: str | bytes | bytearray | memoryview | None = None,
) -> dict[str, object]:
    """Return a safe status mapping suitable for API/CLI responses."""

    signature = certificate.signature
    return {
        "signed": signature is not None,
        "valid": verify_certificate_signature(certificate, verification_key)
        if signature is not None and verification_key is not None
        else False,
        "algorithm": signature.algorithm if signature is not None else None,
        "key_id": signature.key_id if signature is not None else None,
    }


__all__ = [
    "CertificateSigner",
    "CertificateSigningError",
    "HMACSHA256Signer",
    "HMACSigner",
    "canonical_certificate_payload",
    "certificate_signature_status",
    "sign_certificate",
    "signer_from_key",
    "verify_certificate_signature",
]
