"""
Cryptographic utilities for Uniplex.

Uses Ed25519 for signatures - compact, fast, and widely supported.
"""

import base64
import json
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a new Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_bytes(key: Ed25519PrivateKey) -> bytes:
    """Serialize private key to raw bytes."""
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_bytes(key: Ed25519PublicKey) -> bytes:
    """Serialize public key to raw bytes."""
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_from_bytes(data: bytes) -> Ed25519PrivateKey:
    """Load private key from raw bytes."""
    return Ed25519PrivateKey.from_private_bytes(data)


def public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    """Load public key from raw bytes."""
    return Ed25519PublicKey.from_public_bytes(data)


def encode_base64(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_base64(s: str) -> bytes:
    """Decode URL-safe base64 string (handles missing padding)."""
    # Add padding if needed
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message with Ed25519."""
    return private_key.sign(message)


def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def canonical_json(obj: dict) -> bytes:
    """
    Produce canonical JSON for signing.
    
    Per spec: keys sorted, no whitespace, UTF-8 encoded.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
