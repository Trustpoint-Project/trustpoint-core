"""This module contains serializers for certificates and keys."""

from __future__ import annotations


from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, pkcs12

from trustpoint_core.types import PrivateKey, PublicKey
import typing


def load_pkcs12_bytes(
    p12: bytes, password: bytes | None = None
) -> pkcs12.PKCS12KeyAndCertificates:
    """Tries to load a PKCS#12 bytes object.

    Args:
        p12: The bytes object containing the PKCS#12 data structure.
        password: The password to decrypt the PKCS#12 data structure, if any.

    Returns:
        The loaded PKCS12KeyAndCertificates object.

    Raises:
        TypeError: If p12 is not a bytes object or the password is not a bytes object or None.
    """
    if not isinstance(p12, bytes):
        err_msg = f"Expected a bytes object, but got {type(p12)})"
        raise TypeError(err_msg)

    if not isinstance(password, bytes) or password is not None:
        err_msg = f"Expected the password to be a bytes object or None, but got {type(password)})"
        raise TypeError(err_msg)

    try:
        loaded_p12 = pkcs12.load_pkcs12(p12, password)
    except Exception as exception:
        err_msg = (
            "Failed to load PKCS#12 bytes. Either wrong password or malformed data."
        )
        raise ValueError(err_msg) from exception

    return loaded_p12


def get_encryption_algorithm(
    password: None | bytes = None,
) -> serialization.KeySerializationEncryption:
    """Returns the encryption algorithm to use.

    Args:
        password: A password to use, if any.

    Returns:
        If a password is provided, BestAvailableEncryption(password) is returned, otherwise NoEncryption()
    """
    if password:
        return serialization.BestAvailableEncryption(password)
    return serialization.NoEncryption()


class PublicKeySerializer:
    """The PublicKeySerializer class provides methods for serializing and loading a public key."""

    _public_key: PublicKey
    _pem: bytes | None = None
    _der: bytes | None = None

    def __init__(self, public_key: PublicKey) -> None:
        """Initializes a PublicKeySerializer with the provided public key object.

        Args:
            public_key: The public key object to be serialized.

        Raises:
            TypeError: If the public key is not a PublicKey object.
        """
        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f"Expected a public key object, but got {type(public_key)}."
            raise TypeError(err_msg)

        self._public_key = public_key

    @classmethod
    def from_der(cls, public_key: bytes) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a DER encoded public key.

        Args:
            public_key: The public key as bytes object in DER format.

        Returns:
            The corresponding PublicKeySerializer containing the provided key.

        Raises:
            TypeError: If the public key is not a bytes object.
            ValueError: If loading the public key failed or the contained key type is not supported.
        """
        try:
            loaded_public_key = serialization.load_der_public_key(public_key)
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = "Algorithm found in public key is not supported."
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = (
                f"Expected public_key to be a bytes object, got {type(public_key)}."
            )
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = "Failed to load the public key in DER format. Either wrong format or corrupted public key."
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_public_key, typing.get_args(PublicKey)):
            err_msg = f"The key type {type(loaded_public_key)} is not supported."
            raise ValueError(err_msg)

        return cls(loaded_public_key)

    @classmethod
    def from_pem(cls, public_key: bytes) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a PEM encoded public key.

        Args:
            public_key: The public key as bytes object in PEM format.

        Returns:
            The corresponding PublicKeySerializer containing the provided key.

        Raises:
            TypeError: If the public key is not a bytes object.
            ValueError: If loading the public key failed.
        """
        try:
            loaded_public_key = serialization.load_pem_public_key(public_key)
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = "The algorithm of the provided public key is not supported."
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = (
                f"Expected public_key to be a bytes object, got {type(public_key)}."
            )
            raise TypeError(err_msg) from exception
        except ValueError as exception:
            err_msg = "Failed to load the public key in PEM format. Either wrong format or corrupted public key."
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_public_key, typing.get_args(PublicKey)):
            err_msg = f"The key type {type(loaded_public_key)} is not supported."
            raise ValueError(err_msg)

        return cls(loaded_public_key)

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a private key object.

        Args:
            private_key: The private key object.

        Returns:
            The corresponding PublicKeySerializer containing the public key contained in the provided private key.

        Raises:
            TypeError: If the private key is not a private key object.
        """
        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f"Expected a private key object, but got {type(private_key)}."
            raise TypeError(err_msg)

        return cls(private_key.public_key())

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a certificate object.

        Args:
            certificate: The certificate object.

        Returns:
            The corresponding PublicKeySerializer containing the provided key contained in the certificate.

        Raises:
            TypeError: If the private key is not a private key object.
            ValueError: If the key type is not supported.
        """
        if not isinstance(certificate, x509.Certificate):
            err_msg = f"Expected a certificate object, but got {type(certificate)}."
            raise TypeError(err_msg)

        public_key = certificate.public_key()
        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f"The key type {type(public_key)} is not supported."
            raise ValueError(err_msg)

        return cls(public_key)

    def as_crypto(self) -> PublicKey:
        """Gets the contained public key object.

        Returns:
            The contained public key object.
        """
        return self._public_key

    def as_der(self) -> bytes:
        """Gets the contained public key as DER encoded bytes.

        Returns:
            The contained public key as DER encoded bytes.
        """
        if self._der is None:
            self._der = self._public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return self._der

    def as_pem(self) -> bytes:
        """Gets the contained public key as PEM encoded bytes.

        Returns:
            The contained public key as PEM encoded bytes.
        """
        if self._pem is None:
            self._pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return self._pem


class PrivateKeySerializer:
    """The PrivateKeySerializer class provides methods for serializing and loading a private key."""

    _private_key: PrivateKey

    def __init__(self, private_key: PrivateKey) -> None:
        """Initializes a PrivateKeySerializer with the provided private key object.

        Args:
            private_key: The private key object to be serialized.

        Raises:
            TypeError: If the private key is not a PrivateKey object.
        """
        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f"Expected a private key object, but got {type(private_key)}."
            raise TypeError(err_msg)

        self._private_key = private_key

    @classmethod
    def from_pem(cls, private_key: bytes, password: bytes | None = None):
        """Creates a PrivateKeySerializer from a PEM encoded public key.

        Args:
            private_key: The private key as bytes object in PEM format.
            password: The password to encrypt the private key with

        Returns:
            The corresponding PrivateKeySerializer containing the provided key.

        Raises:
            TypeError: If the private key is not a bytes object.
            ValueError: If loading the private key failed.
        """
        if not isinstance(private_key, bytes):
            err_msg = (
                f"Expected private_key to be a bytes object, got {type(private_key)}."
            )
            raise TypeError(err_msg)

        try:
            loaded_private_key = serialization.load_pem_private_key(
                private_key, password
            )
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = "The algorithm of the provided private key is not supported."
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = "Wrong password to encrypt the private key."
            raise ValueError(err_msg) from exception
        except Exception as exception:
            err_msg = "Failed to load the private key in PEM format. Either wrong format or corrupted public key."
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_private_key, typing.get_args(PrivateKey)):
            err_msg = f"The key type {type(loaded_private_key)} is not supported."
            raise ValueError(err_msg)

        return cls(loaded_private_key)

    @classmethod
    def from_der(cls, private_key: bytes, password: bytes | None = None):
        """Creates a PrivateKeySerializer from a DER encoded public key.

        Args:
            private_key: The private key as bytes object in DER format.
            password: The password to encrypt the private key with

        Returns:
            The corresponding PrivateKeySerializer containing the provided key.

        Raises:
            TypeError: If the private key is not a bytes object.
            ValueError: If loading the private key failed.
        """
        if not isinstance(private_key, bytes):
            err_msg = (
                f"Expected private_key to be a bytes object, got {type(private_key)}."
            )
            raise TypeError(err_msg)

        try:
            loaded_private_key = serialization.load_der_private_key(
                private_key, password
            )
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = "The algorithm of the provided private key is not supported."
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = "Wrong password to encrypt the private key."
            raise ValueError(err_msg) from exception
        except Exception as exception:
            err_msg = "Failed to load the private key in DER format. Either wrong format or corrupted public key."
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_private_key, typing.get_args(PrivateKey)):
            err_msg = f"The key type {type(loaded_private_key)} is not supported."
            raise ValueError(err_msg)

        return cls(loaded_private_key)

    @classmethod
    def from_pkcs12_bytes(
        cls, p12: bytes, password: bytes | None = None
    ) -> PrivateKeySerializer:
        """Creates a PrivateKeySerializer from a PKCS#12 bytes object.

        Args:
            p12: The PKCS#12 bytes object.
            password: The password to encrypt the private key with

        Returns:
            The corresponding PrivateKeySerializer containing the provided key.

        Raises:
            TypeError: If the private key is not a bytes object.
            ValueError: If loading the private key failed.
        """
        loaded_p12 = load_pkcs12_bytes(p12, password)
        return cls.from_pkcs12(loaded_p12)

    @classmethod
    def from_pkcs12(cls, p12: pkcs12.PKCS12KeyAndCertificates) -> PrivateKeySerializer:
        """Creates a PrivateKeySerializer from a PKCS#12 object.

        Args:
            p12: The PKCS#12 object.

        Returns:
            The corresponding PrivateKeySerializer containing the provided key.

        Raises:
            TypeError: If the private key is not a PKCS#12 object.
            ValueError: If loading the private key failed.
        """
        if not p12.key:
            err_msg = "The provided PKCS#12 object does not contain a private key."
            raise ValueError(err_msg)

        private_key = p12.key

        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f"The key type {type(private_key)} is not supported."
            raise ValueError(err_msg)

        return cls(private_key)

    def as_pkcs1_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            Bytes that contain the private key in PKCS#1 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def as_pkcs1_pem(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 PEM format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            Bytes that contain the private key in PKCS#1 PEM format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def as_pkcs8_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            Bytes that contain the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def as_pkcs8_pem(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            Bytes that contain the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def as_pkcs12(
        self, password: None | bytes = None, friendly_name: bytes = b""
    ) -> bytes:
        """Gets the associated private key as bytes in a PKCS#12 structure.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            Bytes that contain the private key in a PKCS#12 structure.
        """
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self._private_key,
            cert=None,
            cas=None,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def as_crypto(self) -> PrivateKey:
        """Gets the associated private key as PrivateKey instance.

        Returns:
            The associated private key as PrivateKey instance.
        """
        return self._private_key

    @property
    def public_key_serializer(self) -> PublicKeySerializer:
        """Gets the PublicKeySerializer instance of the associated private key.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance of the associated private key.
        """
        return PublicKeySerializer(self._private_key.public_key())


class CertificateSerializer:
    """The CertificateSerializer class provides methods for serializing and loading a certificate."""

    _certificate: x509.Certificate
    _public_key_serializer: PublicKeySerializer | None = None

    _pem: bytes | None = None
    _der: bytes | None = None
    _pkcs7_pem: bytes | None = None
    _pkcs7_der: bytes | None = None

    def __init__(self, certificate: x509.Certificate) -> None:
        """Initializes a CertificateSerializer with the provided certificate object.

        Args:
            certificate: The certificate object to be serialized.

        Raises:
            TypeError: If certificate is not a Certificate object.
        """
        if not isinstance(certificate, x509.Certificate):
            err_msg = f"Expected a certificate object, but got {type(certificate)}."
            raise TypeError(err_msg)
        self._certificate = certificate

    @classmethod
    def from_pem(cls, certificate: bytes) -> CertificateSerializer:
        """Creates a CertificateSerializer from a certificate bytes object in PEM format.

        Args:
            certificate: The certificate as a bytes object in PEM format.

        Returns:
            The corresponding CertificateSerializer.

        Raises:
            TypeError: If the certificate is not a bytes object.
            ValueError: If loading the certificate failed.
        """
        try:
            loaded_certificate = x509.load_pem_x509_certificate(certificate)
        except TypeError as exception:
            err_msg = f"Expected the certificate to be a bytes object, got {type(certificate)}."
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                "Failed to load the provided certificate in PEM format. "
                "Either wrong format or data is corrupted."
            )
            raise ValueError(err_msg) from exception

        return cls(loaded_certificate)

    @classmethod
    def from_der(cls, certificate: bytes) -> CertificateSerializer:
        """Creates a CertificateSerializer from a certificate bytes object in DER format.

        Args:
            certificate: The certificate as a bytes object in DER format.

        Returns:
            The corresponding CertificateSerializer.

        Raises:
            TypeError: If the certificate is not a bytes object.
            ValueError: If loading the certificate failed.
        """
        try:
            loaded_certificate = x509.load_der_x509_certificate(certificate)
        except TypeError as exception:
            err_msg = f"Expected the certificate to be a bytes object, got {type(certificate)}."
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                "Failed to load the provided certificate in DER format. "
                "Either wrong format or data is corrupted."
            )
            raise ValueError(err_msg) from exception

        return cls(loaded_certificate)

    def as_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PEM format.

        Returns:
            Bytes that contain the certificate in PEM format.
        """
        if self._pem is None:
            self._pem = self._certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            )
        return self._pem

    def as_der(self) -> bytes:
        """Gets the associated certificate as bytes in DER format.

        Returns:
            Bytes that contain the certificate in DER format.
        """
        if self._der is None:
            self._der = self._certificate.public_bytes(
                encoding=serialization.Encoding.DER
            )
        return self._der

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 PEM format.

        Returns:
            Bytes that contain the certificate in PKCS#7 PEM format.
        """
        if self._pkcs7_pem is None:
            self._pkcs7_pem = pkcs7.serialize_certificates(
                [self._certificate], serialization.Encoding.PEM
            )
        return self._pkcs7_pem

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 DER format.

        Returns:
            Bytes that contain the certificate in PKCS#7 DER format.
        """
        if self._pkcs7_der is None:
            self._pkcs7_der = pkcs7.serialize_certificates(
                [self._certificate], serialization.Encoding.DER
            )
        return self._pkcs7_der

    def as_crypto(self) -> x509.Certificate:
        """Gets the associated certificate as x509.Certificate instance.

        Returns:
            The associated certificate as x509.Certificate instance.
        """
        return self._certificate

    @property
    def public_key(self) -> PublicKey:
        """Property to get the public key object.

        Returns:
            The public key object.
        """
        return self.public_key_serializer.as_crypto()

    @property
    def public_key_serializer(self) -> PublicKeySerializer:
        """Property to get the corresponding PublicKeySerializer object (lazy loading).

        Returns:
            The corresponding PublicKeySerializer object.
        """
        if self._public_key_serializer is None:
            public_key = self._certificate.public_key()
            if not isinstance(public_key, typing.get_args(PublicKey)):
                err_msg = f"Expected a public key object, but got {type(public_key)}."
                raise TypeError(err_msg)

            self._public_key_serializer = PublicKeySerializer(public_key)
        return self._public_key_serializer

    @staticmethod
    def _load_pem_certificate(certificate_data: bytes) -> x509.Certificate:
        try:
            return x509.load_pem_x509_certificate(certificate_data)
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_der_certificate(certificate_data: bytes) -> x509.Certificate:
        try:
            return x509.load_der_x509_certificate(certificate_data)
        except Exception as exception:
            raise ValueError from exception


class CertificateCollectionSerializer:
    """The CertificateCollectionSerializer class provides methods for serializing and loading certificate collections.

    Certificate collections are lists of single certificates. The order will be preserved. Usually these collections
    will either be a certificate chain or a trust store.

    Warnings:
        The CertificateCollectionSerializer class does not evaluate or validate any contents of the certificate
        collection, i.e. no certificate chains are validated.
    """

    _certificates: list[x509.Certificate]

    def __init__(self, certificates: list[x509.Certificate]) -> None:
        """Initializes a CertificateCollectionSerializer with the provided list of certificate objects.

        Args:
            certificates: A list of certificate objects or an emtpy list.
        """
        if not isinstance(certificates, list):
            err_msg = "CertificateCollectionSerializer requires a list of certificate objects."
            raise TypeError(err_msg)

        for certificate in certificates:
            if not isinstance(certificate, x509.Certificate):
                err_msg = (
                    "The provided list of certificates contains at least "
                    "one object that is not a certificate object."
                )
                raise TypeError(err_msg)

        self._certificates = certificates

    @classmethod
    def from_list_of_der(
        cls, certificates: list[bytes]
    ) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a list of certificates as byte objects in DER format.

        Args:
            certificates: A list of certificates as byte objects in DER format.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If certificates is not a list of bytes.
            ValueError: If loading os the certificates failed.
        """
        loaded_certificates = []
        for certificate in certificates:
            try:
                loaded_certificates.append(x509.load_der_x509_certificate(certificate))
            except TypeError as exception:
                err_msg = f"Expected the certificate to be a bytes object, got {type(certificate)}."
                raise TypeError(err_msg) from exception
            except Exception as exception:
                err_msg = (
                    "Failed to load the provided certificate in DER format. "
                    "Either wrong format or data is corrupted."
                )
                raise ValueError(err_msg) from exception

        return cls(loaded_certificates)

    @classmethod
    def from_list_of_pem(
        cls, certificates: list[bytes]
    ) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a list of certificates as byte objects in PEM format.

        Args:
            certificates: A list of certificates as byte objects in PEM format.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If certificates is not a list of bytes.
            ValueError: If loading of the certificates failed.
        """
        loaded_certificates = []
        for certificate in certificates:
            try:
                loaded_certificates.append(x509.load_pem_x509_certificate(certificate))
            except TypeError as exception:
                err_msg = f"Expected the certificate to be a bytes object, got {type(certificate)}."
                raise TypeError(err_msg) from exception
            except Exception as exception:
                err_msg = (
                    "Failed to load the provided certificate in PEM format. "
                    "Either wrong format or data is corrupted."
                )
                raise ValueError(err_msg) from exception

        return cls(loaded_certificates)

    @classmethod
    def from_pem(cls, certificates: bytes) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a list of certificates as byte objects in DER format.

        Args:
            certificates: A bytes object containing one or more PEM encoded certificates.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If certificates is not a list of bytes.
            ValueError: If loading of the certificates failed.
        """
        try:
            loaded_certificates = x509.load_pem_x509_certificates(certificates)
        except TypeError as exception:
            err_msg = (
                "Expected certificates to be a bytes object containing certificates in PEM format, "
                f"but got {type(certificates)}."
            )
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                "Failed to load the provided certificates in PEM format. "
                "Either wrong format or data is corrupted."
            )
            raise ValueError(err_msg) from exception

        return cls(loaded_certificates)

    @classmethod
    def from_pkcs7_der(cls, certificates: bytes) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a PKCS#7 structure containing DER encoded certificates.

        Only unencrypted and unsigned PKCS#7 files are supported at this point in time.

        Args:
            certificates: A PKCS#7 structure containing DER encoded certificates.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If certificates is not bytes object.
            ValueError: If loading of the certificates failed.
        """
        try:
            loaded_certificates = pkcs7.load_der_pkcs7_certificates(certificates)
        except TypeError as exception:
            err_msg = (
                "Expected certificates to be a bytes object containing certificates in PEM format, "
                f"but got {type(certificates)}."
            )
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                "Failed to load the provided certificates in PEM format. "
                "Either wrong format or data is corrupted."
            )
            raise ValueError(err_msg) from exception

        return cls(loaded_certificates)

    @classmethod
    def from_pkcs7_pem(cls, certificates: bytes) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a PKCS#7 structure containing PEM encoded certificates.

        Only unencrypted and unsigned PKCS#7 files are supported at this point in time.

        Args:
            certificates: A PKCS#7 structure containing PEM encoded certificates.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If certificates is not bytes object.
            ValueError: If loading of the certificates failed.
        """
        try:
            loaded_certificates = pkcs7.load_pem_pkcs7_certificates(certificates)
        except TypeError as exception:
            err_msg = (
                "Expected certificates to be a bytes object containing certificates in PEM format, "
                f"but got {type(certificates)}."
            )
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                "Failed to load the provided certificates in PEM format. "
                "Either wrong format or data is corrupted."
            )
            raise ValueError(err_msg) from exception

        return cls(loaded_certificates)

    @classmethod
    def from_pkcs12_bytes(
        cls, p12: bytes, password: bytes | None = None
    ) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a PKCS#12 structure including the credential certificate.

        Args:
            p12: A PKCS#12 structure.
            password: The password to decrypt the PKCS#12 file.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If p12 is not a PKCS12KeyAndCertificates object.
            ValueError: If loading of the PKCS12KeyAndCertificates failed.
        """
        loaded_p12 = load_pkcs12_bytes(p12, password)
        return cls.from_pkcs12(loaded_p12)

    @classmethod
    def from_pkcs12(
        cls, p12: pkcs12.PKCS12KeyAndCertificates
    ) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a PKCS#12 structure including the credential certificate.

        Args:
            p12: A PKCS#12 structure.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If p12 is not a PKCS12KeyAndCertificates object.
            ValueError: If loading of the PKCS12KeyAndCertificates failed.
        """
        if not isinstance(p12, pkcs12.PKCS12KeyAndCertificates):
            err_msg = f"Expected p12 to be a PKCS12KeyAndCertificates object, but got {type(p12)}."
            raise TypeError(err_msg)

        p12_certificate = p12.cert.certificate if p12.cert else None
        p12_additional_certificates = (
            p12.additional_certs if p12.additional_certs else []
        )

        certificates = [cert.certificate for cert in p12_additional_certificates]
        if p12_certificate:
            certificates.append(p12_certificate)

        return cls(certificates)

    @classmethod
    def from_pkcs12_bytes_additional_certs_only(
        cls, p12: bytes, password: bytes | None = None
    ) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a PKCS#12 structure excluding the credential certificate.

        Args:
            p12: A PKCS#12 structure.
            password: The password to decrypt the PKCS#12 file.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If p12 is not a PKCS12KeyAndCertificates object.
            ValueError: If loading of the PKCS12KeyAndCertificates failed.
        """
        loaded_p12 = load_pkcs12_bytes(p12, password)
        return cls.from_pkcs12_additional_certs_only(loaded_p12)

    @classmethod
    def from_pkcs12_additional_certs_only(
        cls, p12: pkcs12.PKCS12KeyAndCertificates
    ) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a PKCS#12 structure excluding the credential certificate.

        Args:
            p12: A PKCS#12 structure.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If p12 is not a PKCS12KeyAndCertificates object.
            ValueError: If loading of the PKCS12KeyAndCertificates failed.
        """
        if not isinstance(p12, pkcs12.PKCS12KeyAndCertificates):
            err_msg = f"Expected p12 to be a PKCS12KeyAndCertificates object, but got {type(p12)}."
            raise TypeError(err_msg)

        p12_additional_certificates = (
            p12.additional_certs if p12.additional_certs else []
        )
        certificates = [cert.certificate for cert in p12_additional_certificates]

        return cls(certificates)

    def __add__(
        self,
        other: x509.Certificate
        | CertificateSerializer
        | CertificateCollectionSerializer,
    ) -> CertificateCollectionSerializer:
        """Adds certificates to the CertificateCollectionSerializer.

        Args:
            other: The certificate or certificates to add.

        Returns:
            A new CertificateCollectionSerializer instance containing the sum of the certificates.
        """
        if isinstance(other, x509.Certificate):
            return CertificateCollectionSerializer([other, *self._certificates])
        elif isinstance(other, CertificateSerializer):
            if other.as_crypto() in self._certificates:
                return CertificateCollectionSerializer(self._certificates)
            return CertificateCollectionSerializer(
                [other.as_crypto(), *self._certificates]
            )
        elif isinstance(other, CertificateCollectionSerializer):
            return CertificateCollectionSerializer(
                list(set(self._certificates + other._certificates))
            )
        else:
            err_msg = (
                "Only CertificateSerializer and CertificateCollectionSerializers can be added to a"
                "CertificateCollectionSerializer."
            )
            raise TypeError(err_msg)

    def __len__(self) -> int:
        """Gets the number of contained certificates.

        Returns:
            Returns the number of certificates contained in this credential.
        """
        return len(self._certificates)

    def as_crypto(self) -> list[x509.Certificate]:
        """Gets the associated certificate collection as list of x509.Certificate instances.

        Returns:
            List of x509.Certificate instances.
        """
        return self._certificates

    def as_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PEM format.

        Returns:
            Bytes that contain the certificate collection in PEM format.
        """
        return b"".join(self.as_pem_list())

    def as_pem_list(self) -> list[bytes]:
        """Gets the certificates as list of PEM encoded bytes.

        Returns:
            Certificates as list of PEM encoded bytes.
        """
        return [
            CertificateSerializer(certificate).as_pem()
            for certificate in self._certificates
        ]

    def as_der_list(self) -> list[bytes]:
        """Gets the certificates as list of DER encoded bytes.

        Returns:
            Certificates as list of DER encoded bytes.
        """
        return [
            CertificateSerializer(certificate).as_der()
            for certificate in self._certificates
        ]

    def as_certificate_serializer_list(self) -> list[CertificateSerializer]:
        """Gets the certificates as list of CertificateSerializer instances.

        Returns:
            Certificates as list of CertificateSerializer instances.
        """
        return [
            CertificateSerializer(certificate) for certificate in self._certificates
        ]

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 PEM format.

        Returns:
            Bytes that contain certificate collection in PKCS#7 PEM format.
        """
        return pkcs7.serialize_certificates(
            self.as_crypto(), serialization.Encoding.PEM
        )

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 DER format.

        Returns:
            bytes: Bytes that contain certificate collection in PKCS#7 DER format.
        """
        return pkcs7.serialize_certificates(
            self.as_crypto(), serialization.Encoding.DER
        )


class CredentialSerializer:
    """The CredentialSerializer class provides methods for serializing and loading X.509 Credentials.

    A complete credential consists of a private key, a matching certificate and the full chain including the root ca.

    However, this object can also be used for partial credentials, e.g. missing private key or only parts or no
    certificate chain at all.
    """

    _private_key: PrivateKey | None
    _certificate: x509.Certificate | None
    _additional_certificates: list[x509.Certificate]

    def __init__(
        self,
        private_key: PrivateKey | None = None,
        certificate: x509.Certificate | None = None,
        additional_certificates: list[x509.Certificate] | None = None,
    ) -> None:
        """Initializes a CredentialSerializer with the provided list of certificate objects.

        Args:
            private_key: The private key associated with this credential, if any.
            certificate: The certificate associated with this credential and private key.
            additional_certificates:
            The certificate chain associated with this credential, which may or may not be complete or missing at all.
        """
        self.private_key = private_key
        self.certificate = certificate
        if additional_certificates is None:
            self.additional_certificates = []
        else:
            self.additional_certificates = additional_certificates

    @property
    def private_key(self) -> PrivateKey | None:
        """Gets the associated credential private key.

        Returns:
            Returns the associated credential private key.
        """
        return self._private_key

    @private_key.setter
    def private_key(self, private_key: PrivateKey | None) -> None:
        """Sets the associated credential private key to the provided one or to None.

        Args:
            private_key: The credential private key to associate with this credential or None.

        Raises:
            TypeError: If the provided private key is not a PrivateKey object or None.
        """
        if private_key is not None and not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f"The private_key must be of type PrivateKey or None, but got {type(private_key)}."
            raise TypeError(err_msg)
        self._private_key = private_key

    @private_key.deleter
    def private_key(self) -> None:
        """Sets the associated credential private key to None."""
        self._private_key = None

    @property
    def certificate(self) -> x509.Certificate | None:
        """Gets the associated credential certificate.

        Returns:
            Returns the associated credential certificate.
        """
        return self._certificate

    @certificate.setter
    def certificate(self, certificate: x509.Certificate | None) -> None:
        """Sets the associated credential certificate to the provided one or to None.

        Args:
            certificate: The credential certificate to associate with this credential or None.

        Raises:
            TypeError: If the provided certificate is not a Certificate object or None.
        """
        if certificate is not None and not isinstance(certificate, x509.Certificate):
            err_msg = f"The certificate must be of type Certificate or None, but got {type(certificate)}."
            raise TypeError(err_msg)
        self._certificate = certificate

    @certificate.deleter
    def certificate(self) -> None:
        """Sets the associated credential certificate to None."""
        self._certificate = None

    @property
    def additional_certificates(self) -> list[x509.Certificate]:
        """Gets the associated additional certificates.

        Returns:
            Returns the associated additional certificates.
        """
        return self._additional_certificates

    @additional_certificates.setter
    def additional_certificates(self, additional_certificates: list | None) -> None:
        """Sets the associated additional certificates to the provided ones or an emtpy list..

        Args:
            additional_certificates: The additional certificates to associate with this credential or None.

        Raises:
            TypeError: If the provided certificate is not a list of Certificate objects or None.
        """
        if additional_certificates is None:
            self._additional_certificates = []
        elif isinstance(additional_certificates, list):
            for certificate in additional_certificates:
                if not isinstance(certificate, x509.Certificate):
                    err_msg = (
                        "All elements contained in the list must be of type Certificate, "
                        f"but at least one is of type {type(certificate)}."
                    )
                    raise TypeError(err_msg)
                self._additional_certificates = additional_certificates
        err_msg = (
            "The additional_certificates must be None or a list of Certificate objects, "
            f"but got {type(additional_certificates)}."
        )
        raise TypeError(err_msg)

    @additional_certificates.deleter
    def additional_certificates(self) -> None:
        """Sets the associated credential certificate to an empty list."""
        self._additional_certificates = []

    @classmethod
    def from_pkcs12_bytes(
        cls, p12: bytes, password: bytes | None = None
    ) -> CredentialSerializer:
        """Creates a CredentialSerializer from a PKCS#12 structure.

        Args:
            p12: A PKCS#12 structure.
            password: The password to decrypt the PKCS#12 file.

        Returns:
            The corresponding CredentialSerializer.

        Raises:
            TypeError: If p12 is not a PKCS12KeyAndCertificates object.
            ValueError: If loading of the PKCS12KeyAndCertificates failed.
        """
        loaded_p12 = load_pkcs12_bytes(p12, password)
        return cls.from_pkcs12(loaded_p12)

    @classmethod
    def from_pkcs12(cls, p12: pkcs12.PKCS12KeyAndCertificates) -> CredentialSerializer:
        """Creates a CredentialSerializer from a PKCS#12 structure.

        Args:
            p12: A PKCS#12 structure.

        Returns:
            The corresponding CredentialSerializer.

        Raises:
            TypeError: If p12 is not a PKCS12KeyAndCertificates object.
            ValueError: If loading of the PKCS12KeyAndCertificates failed.
        """
        if not isinstance(p12, pkcs12.PKCS12KeyAndCertificates):
            err_msg = f'Expected p12 to be a PKCS12KeyAndCertificates object, but got {type(p12)}.'
            raise TypeError(err_msg)

        certificate = p12.cert.certificate if p12.cert else None
        private_key = p12.key

        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = 'Private key found in the PKCS#12 structure is not supported.'
            raise TypeError(err_msg)

        p12_additional_certificates = (
            p12.additional_certs if p12.additional_certs else []
        )
        additional_certificates = [
            cert.certificate for cert in p12_additional_certificates
        ]

        return cls(private_key, certificate, additional_certificates)

    def as_pkcs12(
        self, password: None | bytes = None, friendly_name: bytes = b""
    ) -> bytes:
        """Gets the credential as bytes in PKCS#12 format.

        Args:
            password: Password if the credential shall be encrypted, None otherwise.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            bytes: Bytes that contain the credential in PKCS#12 format.
        """
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self.private_key,
            cert=self.certificate,
            cas=self.additional_certificates,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def normalize(self) -> None:
        """Tries to normalize the credential.

        Normalization:
            This operation will try to determine the certificate chain, order them appropriately, such that
            the certificate that issued the credential certificate will be the first additional certificate and the
            root certificate will be the last certificate. All other certificates will be dropped. This operation will
            not fail if certificates are missing and the chain cannot be constructed. It will just include all
            certificates of the chain that are available.

            This operation will, however, fail if multiple valid chains are contained in the additional certificates.
            Hence, cross-signed certificates with multiple chains will fail and raise a ValueError.

        Raises:
            ValueError: If more than one chain can be constructed out of the additional certificates.
        """
        # In the case that there are is no credential certificate available, drop additional
        if self.certificate is None:
            self.additional_certificates = []
            return

        # If the credential certificate is self-signed,
        try:
            self.certificate.verify_directly_issued_by(self.certificate)
            self._additional_certificates = []
            return
        except (ValueError, TypeError, crypto_exceptions.InvalidSignature):
            pass

        additional_certificates = []

        current_certificate = self.certificate

        # TODO: Could be attacked for circular signature paths. Fix this!
        while current_certificate:
            issuer_certificate = self._get_issuer(current_certificate)
            if issuer_certificate is None or current_certificate == issuer_certificate:
                break
            additional_certificates.append(issuer_certificate)

        self.additional_certificates = additional_certificates

    def _get_issuer(self, certificate: x509.Certificate) -> x509.Certificate | None:
        """Gets the issuer certificate from the additional certificates, None otherwise.

        Args:
            certificate: The certificate for which we are trying to get the issuer certificate for.

        Returns:
            Returns the issuer certificate from the additional certificates, None otherwise.
        """
        for additional_certificate in self.additional_certificates:
            try:
                certificate.verify_directly_issued_by(additional_certificate)
                return additional_certificate
            except (ValueError, TypeError, crypto_exceptions.InvalidSignature):
                pass

        return None

    def __len__(self) -> int:
        """Returns the number of certificates contained in this credential."""
        if self._additional_certificates is None:
            return 1

        return len(self._additional_certificates) + 1
