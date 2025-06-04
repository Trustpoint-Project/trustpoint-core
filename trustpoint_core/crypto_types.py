"""This module defines types used for TYPE_CHECKING."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey
AllowedCertSignHashAlgos = (
    hashes.SHA224
    | hashes.SHA256
    | hashes.SHA384
    | hashes.SHA512
    | hashes.SHA3_224
    | hashes.SHA3_256
    | hashes.SHA3_384
    | hashes.SHA3_512
)
