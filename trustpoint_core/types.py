"""This module defines types used for TYPE_CHECKING."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Union
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed448,
        ed25519,
        rsa,
        x448,
        x25519,
        dh,
    )

    PublicKey = Union[
        dh.DHPublicKey,
        dsa.DSAPublicKey,
        rsa.RSAPublicKey,
        ec.EllipticCurvePublicKey,
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
        x25519.X25519PublicKey,
        x448.X448PublicKey,
    ]
    PrivateKey = Union[
        dh.DHPrivateKey,
        dsa.DSAPrivateKey,
        rsa.RSAPrivateKey,
        ec.EllipticCurvePrivateKey,
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
        x25519.X25519PrivateKey,
        x448.X448PrivateKey,
    ]