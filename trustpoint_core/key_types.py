"""This module defines types used for TYPE_CHECKING."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | ed448.Ed448PrivateKey
