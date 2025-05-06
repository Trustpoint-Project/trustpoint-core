"""This module contains serializers for certificates and keys."""

from __future__ import annotations

import enum
import typing

from cryptography import exceptions as crypto_exceptions
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, pkcs7, pkcs12

from trustpoint_core.key_types import PrivateKey, PublicKey

if typing.TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Self


class CertificateFormat(enum.Enum):
    """Supported certificate formats."""

    mime_type: str
    file_extension: str

    PEM = ('pem', 'application/x-pem-file', '.pem')
    DER = ('der', 'application/pkix-cert', '.cer')
    PKCS7_PEM = ('pkcs7_pem', 'application/x-pkcs7-certificates', '.p7b')
    PKCS7_DER = ('pkcs7_der', 'application/x-pkcs7-certificates', '.p7b')

    def __new__(cls, value: None | str, mime_type: str = '', file_extension: str = '') -> Self:
        """Extends the enum with a mime_type and file_extension.

        Args:
            value: The value to set.
            mime_type: The mime type to set.
            file_extension: The file extension to set.

        Returns:
            CertificateFileFormat: The constructed enum.
        """
        if value is None:
            err_msg = 'None is not a valid certificate file format.'
            raise ValueError(err_msg)

        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj


class CredentialFileFormat(enum.Enum):
    """Supported credential file formats, usually used for download and upload features."""

    mime_type: str
    file_extension: str

    PKCS12 = ('pkcs12', 'application/pkcs12', '.p12')
    PEM_ZIP = ('pem_zip', 'application/zip', '.zip')
    PEM_TAR_GZ = ('pem_tar_gz', 'application/gzip', '.tar.gz')

    def __new__(cls, value: None | str, mime_type: str = '', file_extension: str = '') -> Self:
        """Extends the enum with a mime_type and file_extension.

        Args:
            value: The value to set.
            mime_type: The mime type to set.
            file_extension: The file extension to set.

        Returns:
            CredentialFileFormat: The constructed enum.
        """
        if value is None:
            err_msg = 'None is not a valid certificate file format.'
            raise ValueError(err_msg)

        obj = object.__new__(cls)
        obj._value_ = value
        obj.mime_type = mime_type
        obj.file_extension = file_extension
        return obj


def load_pkcs12_bytes(p12: bytes, password: bytes | None = None) -> pkcs12.PKCS12KeyAndCertificates:
    """Tries to load a PKCS#12 bytes object.

    Args:
        p12: The bytes object containing the PKCS#12 data structure.
        password: The password to decrypt the PKCS#12 data structure, if any.

    Returns:
        The loaded PKCS12KeyAndCertificates object.

    Raises:
        TypeError: If the p12 is not a bytes object or the password is not None or a bytes object.
        ValueError: If parsing and loading of the PKCS#12 file failed.
    """
    try:
        loaded_p12 = pkcs12.load_pkcs12(p12, password)
    except TypeError as exception:
        err_msg = (
            f'Expected p12 to be bytes and the password to be bytes or None, but got {type(p12)} and {type(password)}.'
        )
        raise TypeError(err_msg) from exception
    except Exception as exception:
        err_msg = 'Failed to load PKCS#12 bytes. Either wrong password or malformed data.'
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

    Raises:
        ValueError if getting the BestAvailableEncryption algorithm failed.
    """
    if password is None:
        return serialization.NoEncryption()

    try:
        return serialization.BestAvailableEncryption(password)
    except Exception as exception:
        err_msg = 'Failed to get the BestAvailableEncryption algorithm.'
        raise ValueError(err_msg) from exception


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
            TypeError: If the public key is not a supported public key object.
        """
        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f'Expected a public key object, but got {type(public_key)}.'
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
            TypeError: If the public key is not a bytes object or the key type is not supported.
            ValueError: If loading the public key failed.
        """
        try:
            loaded_public_key = serialization.load_der_public_key(public_key)
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = 'Algorithm found in public key is not supported.'
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = f'Expected public_key to be a bytes object, got {type(public_key)}.'
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = 'Failed to load the public key in DER format. Either wrong format or corrupted public key.'
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_public_key, typing.get_args(PublicKey)):
            err_msg = f'The key type {type(loaded_public_key)} is not supported.'
            raise TypeError(err_msg)

        return cls(loaded_public_key)

    @classmethod
    def from_pem(cls, public_key: bytes) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a PEM encoded public key.

        Args:
            public_key: The public key as bytes object in PEM format.

        Returns:
            The corresponding PublicKeySerializer containing the provided key.

        Raises:
            TypeError: If the public key is not a bytes object or the key type is not supported.
            ValueError: If loading the public key failed.
        """
        try:
            loaded_public_key = serialization.load_pem_public_key(public_key)
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = 'The algorithm of the provided public key is not supported.'
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = f'Expected public_key to be a bytes object, got {type(public_key)}.'
            raise TypeError(err_msg) from exception
        except ValueError as exception:
            err_msg = 'Failed to load the public key in PEM format. Either wrong format or corrupted public key.'
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_public_key, typing.get_args(PublicKey)):
            err_msg = f'The key type {type(loaded_public_key)} is not supported.'
            raise TypeError(err_msg)

        return cls(loaded_public_key)

    @classmethod
    def from_bytes(cls, public_key: bytes) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a public key in bytes in PEM or DER format.

        Args:
            public_key:  The public key as a bytes object in PEM or DER format.

        Returns:
            The corresponding PublicKeySerializer containing the provided public key.

        Raises:
            TypeError: If the public key is not a bytes object or the key type is not supported.
            ValueError: If loading the public key failed.
        """
        loaders: list[Callable[[bytes], PublicKeySerializer]] = [
            cls.from_pem,
            cls.from_der,
        ]
        err_msg = 'Failed to load public key. Either wrong format or corrupted public key.'
        for loader in loaders:
            try:
                return loader(public_key)
            except (TypeError, ValueError):
                pass
            except Exception as exception:
                raise ValueError(err_msg) from exception
        raise ValueError(err_msg)

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a private key object.

        Args:
            private_key: The private key object.

        Returns:
            The corresponding PublicKeySerializer containing the public key contained in the provided private key.

        Raises:
            TypeError: If the private key is not a private key object, or the key type is not supported.
        """
        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f'Expected a private key object, but got {type(private_key)}.'
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
            AttributeError: If the certificate does not provide a public_key() method to extract the public key.
            ValueError: If no public key was found in the provided certificate object.
            TypeError: If the key type is not supported.
        """
        try:
            public_key = certificate.public_key()
        except Exception as exception:
            err_msg = f'Object of type {type(certificate)} does not have a public_key() method.'
            raise TypeError(err_msg) from exception

        if public_key is None:
            err_msg = 'No public key found within the certificate.'
            raise ValueError(err_msg)

        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f'The key type {type(public_key)} is not supported.'
            raise TypeError(err_msg)

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
            TypeError: If the private key is not a PrivateKey object or, the key type is not supported.
        """
        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f'Expected a private key object, but got {type(private_key)}.'
            raise TypeError(err_msg)

        self._private_key = private_key

    @classmethod
    def from_pem(cls, private_key: bytes, password: bytes | None = None) -> PrivateKeySerializer:
        """Creates a PrivateKeySerializer from a PEM encoded public key.

        Args:
            private_key: The private key as a bytes object in PEM format.
            password: The password to encrypt the private key with

        Returns:
            The corresponding PrivateKeySerializer containing the provided key.

        Raises:
            TypeError: If the private key type is not supported.
            ValueError: If loading the private key failed.
        """
        if not isinstance(private_key, bytes):
            err_msg = f'Expected private_key to be a bytes object, got {type(private_key)}.'
            raise TypeError(err_msg)

        try:
            loaded_private_key = serialization.load_pem_private_key(private_key, password)
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = 'The algorithm of the provided private key is not supported.'
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = 'Wrong password to encrypt the private key.'
            raise ValueError(err_msg) from exception
        except Exception as exception:
            err_msg = 'Failed to load the private key in PEM format. Either wrong format or corrupted public key.'
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_private_key, typing.get_args(PrivateKey)):
            err_msg = f'The key type {type(loaded_private_key)} is not supported.'
            raise TypeError(err_msg)

        return cls(loaded_private_key)

    @classmethod
    def from_der(cls, private_key: bytes, password: bytes | None = None) -> PrivateKeySerializer:
        """Creates a PrivateKeySerializer from a DER encoded public key.

        Args:
            private_key: The private key as bytes object in DER format.
            password: The password to encrypt the private key with

        Returns:
            The corresponding PrivateKeySerializer containing the provided key.

        Raises:
            TypeError: If the private key type is not supported.
            ValueError: If loading the private key failed.
        """
        if not isinstance(private_key, bytes):
            err_msg = f'Expected private_key to be a bytes object, got {type(private_key)}.'
            raise TypeError(err_msg)

        try:
            loaded_private_key = serialization.load_der_private_key(private_key, password)
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = 'The algorithm of the provided private key is not supported.'
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = 'Wrong password to encrypt the private key.'
            raise ValueError(err_msg) from exception
        except Exception as exception:
            err_msg = 'Failed to load the private key in DER format. Either wrong format or corrupted public key.'
            raise ValueError(err_msg) from exception

        if not isinstance(loaded_private_key, typing.get_args(PrivateKey)):
            err_msg = f'The key type {type(loaded_private_key)} is not supported.'
            raise TypeError(err_msg)

        return cls(loaded_private_key)

    @classmethod
    def from_pkcs12_bytes(cls, p12: bytes, password: bytes | None = None) -> PrivateKeySerializer:
        """Creates a PrivateKeySerializer from a PKCS#12 bytes object.

        Args:
            p12: The PKCS#12 bytes object.
            password: The password to encrypt the private key with

        Returns:
            The corresponding PrivateKeySerializer containing the provided key.

        Raises:
            TypeError: If the private key type is not supported.
            ValueError: If parsing and loading of the PKCS#12 file failed or, no private key is available.
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
            TypeError: If the private key type is not supported.
            ValueError: If no private key is available.
        """
        private_key = p12.key

        if private_key is None:
            err_msg = 'The provided PKCS#12 object does not contain a private key.'
            raise ValueError(err_msg)

        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f'The key type {type(private_key)} is not supported.'
            raise TypeError(err_msg)

        return cls(private_key)

    @classmethod
    def from_bytes(cls, private_key: bytes, password: bytes | None) -> PrivateKeySerializer:
        """Creates a PrivateKeySerializer from a private key in bytes in PEM, DER or PKCS#12 format.

        Args:
            private_key:  The private key as a bytes object in PEM or DER format.
            password: The password to encrypt the private key with if it is encrypted.

        Returns:
            The corresponding PrivateKeySerializer containing the provided private key.

        Raises:
            TypeError: If the private key type is not supported.
            ValueError: If loading the private key failed.
        """
        loaders: list[Callable[[bytes, bytes | None], PrivateKeySerializer]] = [
            cls.from_pem,
            cls.from_der,
            cls.from_pkcs12_bytes,
        ]
        err_msg = 'Failed to load private key. Either wrong format, wrong password or corrupted private key.'
        for loader in loaders:
            try:
                return loader(private_key, password)
            except (TypeError, ValueError):
                pass
            except Exception as exception:
                raise ValueError(err_msg) from exception
        raise ValueError(err_msg)

    def as_pkcs1_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            Bytes object that contains the private key in PKCS#1 DER format.
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
            Bytes object that contains the private key in PKCS#1 PEM format.
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
            Bytes object that contains the private key in PKCS#8 DER format.
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
            Bytes object that contains the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def as_pkcs12(self, password: None | bytes = None, friendly_name: bytes = b'') -> bytes:
        """Gets the associated private key as bytes in a PKCS#12 structure.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            Bytes object that contains the private key in a PKCS#12 structure.
        """
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self._private_key,
            cert=None,
            cas=None,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def as_crypto(self) -> PrivateKey:
        """Gets the associated private key as PrivateKey object.

        Returns:
            The associated private key as PrivateKey object.
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
    _public_key_serializer: PublicKeySerializer

    _pem: bytes | None = None
    _der: bytes | None = None
    _pkcs7_pem: bytes | None = None
    _pkcs7_der: bytes | None = None

    def __init__(self, certificate: x509.Certificate) -> None:
        """Initializes a CertificateSerializer with the provided certificate object.

        Args:
            certificate: The certificate object to be serialized.

        Raises:
            TypeError:
                If certificate is not a Certificate object.
                If the certificate contains an unsupported public key.
        """
        if not isinstance(certificate, x509.Certificate):
            err_msg = f'Expected a certificate object, but got {type(certificate)}.'
            raise TypeError(err_msg)
        self._certificate = certificate

        public_key = certificate.public_key()
        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f'The public key type {type(public_key)} is not supported.'
            raise TypeError(err_msg)

        self._public_key_serializer = PublicKeySerializer(public_key)

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
            err_msg = f'Expected the certificate to be a bytes object, got {type(certificate)}.'
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = 'Failed to load the provided certificate in PEM format. Either wrong format or data is corrupted.'
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
            err_msg = f'Expected the certificate to be a bytes object, got {type(certificate)}.'
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = 'Failed to load the provided certificate in DER format. Either wrong format or data is corrupted.'
            raise ValueError(err_msg) from exception

        return cls(loaded_certificate)

    @classmethod
    def from_bytes(cls, certificate: bytes) -> CertificateSerializer:
        """Creates a CertificateSerializer from a private key in bytes in PEM or DER format.

        Args:
            certificate: The certificate as a bytes object in PEM or DER format.

        Returns:
            The corresponding CertificateSerializer containing the provided certificate.

        Raises:
            TypeError: If the certificate is not a bytes object.
            ValueError: If loading the certificate failed.
        """
        loaders: list[Callable[[bytes], CertificateSerializer]] = [
            cls.from_pem,
            cls.from_der,
        ]
        err_msg = 'Failed to load certificate. Either wrong format or corrupted certificate.'
        for loader in loaders:
            try:
                return loader(certificate)
            except (TypeError, ValueError):
                pass
            except Exception as exception:
                raise ValueError(err_msg) from exception
        raise ValueError(err_msg)

    def as_format(self, certificate_format: CertificateFormat) -> bytes:
        """Returns the certificate as bytes using the provided format.

        Args:
            certificate_format: The certificate format to use.

        Returns:
            The certificate as bytes using the provided format.

        Raises:
            ValueError: If the provided certificate format is not supported.
            TypeError: If an invalid type was provided or an unexpected error occurred.
        """
        try:
            if certificate_format == CertificateFormat.DER:
                return self.as_der()
            if certificate_format == CertificateFormat.PEM:
                return self.as_pem()
            if certificate_format == CertificateFormat.PKCS7_DER:
                return self.as_pkcs7_der()
            if certificate_format == CertificateFormat.PKCS7_PEM:
                return self.as_pkcs7_pem()
        except ValueError:
            raise
        except Exception as exception:
            err_msg = f'Failed to get the the certificate in the requested format. {exception}'
            raise TypeError(err_msg) from exception

        err_msg = f'Invalid certificate format: {certificate_format}'
        raise ValueError(err_msg)

    def as_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PEM format.

        Returns:
            Bytes object that contains the certificate in PEM format.
        """
        if self._pem is None:
            self._pem = self._certificate.public_bytes(encoding=serialization.Encoding.PEM)
        return self._pem

    def as_der(self) -> bytes:
        """Gets the associated certificate as bytes in DER format.

        Returns:
            Bytes object that contains the certificate in DER format.
        """
        if self._der is None:
            self._der = self._certificate.public_bytes(encoding=serialization.Encoding.DER)
        return self._der

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 PEM format.

        Returns:
            Bytes object that contains the certificate in PKCS#7 PEM format.
        """
        if self._pkcs7_pem is None:
            self._pkcs7_pem = pkcs7.serialize_certificates([self._certificate], serialization.Encoding.PEM)
        return self._pkcs7_pem

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 DER format.

        Returns:
            Bytes object that contains the certificate in PKCS#7 DER format.
        """
        if self._pkcs7_der is None:
            self._pkcs7_der = pkcs7.serialize_certificates([self._certificate], serialization.Encoding.DER)
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
        return self._public_key_serializer.as_crypto()

    @property
    def public_key_serializer(self) -> PublicKeySerializer:
        """Property to get the corresponding PublicKeySerializer object (lazy loading).

        Returns:
            The corresponding PublicKeySerializer object.
        """
        return self._public_key_serializer


class CertificateCollectionSerializer:
    """The CertificateCollectionSerializer class provides methods for serializing and loading certificate collections.

    Certificate collections are lists of single certificates. The order will be preserved. Usually these collections
    will either be a certificate chain or a trust store.
    """

    _certificates: list[x509.Certificate]

    def __init__(self, certificates: list[x509.Certificate] | None = None) -> None:
        """Initializes a CertificateCollectionSerializer with the provided list of certificate objects.

        Args:
            certificates: A list of x509.Certificate objects or an emtpy list.

        Raises:
            TypeError: If certificates is not a list of x509.Certificate objects or an empty list.
        """
        if certificates is None:
            self._certificates = []
            return

        if not isinstance(certificates, list):
            err_msg = 'CertificateCollectionSerializer requires a list of certificate objects.'
            raise TypeError(err_msg)

        for certificate in certificates:
            if not isinstance(certificate, x509.Certificate):
                err_msg = (
                    'The provided list of certificates contains at least one object that is not a certificate object.'
                )
                raise TypeError(err_msg)

        self._certificates = certificates

    @classmethod
    def from_list_of_der(cls, certificates: list[bytes]) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a list of certificates as byte objects in DER format.

        Args:
            certificates: A list of certificates as byte objects in DER format or an empty list.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If certificates is not a list of bytes or an empty list.
            ValueError: If loading of one or more contained certificates failed.
        """
        if not isinstance(certificates, list):
            err_msg = f'Expected certificates to be a list, but found {type(certificates)}.'
            raise TypeError(err_msg)

        loaded_certificates = []
        for certificate in certificates:
            try:
                loaded_certificates.append(x509.load_der_x509_certificate(certificate))
            except TypeError as exception:
                err_msg = f'Expected the certificate to be a bytes object, got {type(certificate)}.'
                raise TypeError(err_msg) from exception
            except Exception as exception:
                err_msg = (
                    'Failed to load the provided certificate in DER format. Either wrong format or data is corrupted.'
                )
                raise ValueError(err_msg) from exception

        return cls(loaded_certificates)

    @classmethod
    def from_list_of_pem(cls, certificates: list[bytes]) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a list of certificates as byte objects in PEM format.

        Args:
            certificates: A list of certificates as byte objects in PEM format.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError: If certificates is not a list of bytes or an empty list.
            ValueError: If loading of one or more contained certificates failed.
        """
        if not isinstance(certificates, list):
            err_msg = f'Expected certificates to be a list, but found {type(certificates)}.'
            raise TypeError(err_msg)

        loaded_certificates = []
        for certificate in certificates:
            try:
                loaded_certificates.append(x509.load_pem_x509_certificate(certificate))
            except TypeError as exception:
                err_msg = f'Expected the certificate to be a bytes object, got {type(certificate)}.'
                raise TypeError(err_msg) from exception
            except Exception as exception:
                err_msg = (
                    'Failed to load the provided certificate in PEM format. Either wrong format or data is corrupted.'
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
            TypeError: If certificates is not a bytes object.
            ValueError: If loading of one or more contained certificates failed.
        """
        try:
            loaded_certificates = x509.load_pem_x509_certificates(certificates)
        except TypeError as exception:
            err_msg = (
                'Expected certificates to be a bytes object containing certificates in PEM format, '
                f'but got {type(certificates)}.'
            )
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                'Failed to load the provided certificates in PEM format. Either wrong format or data is corrupted.'
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
            TypeError: If certificates is not a bytes object.
            ValueError: If loading of one or more contained certificates failed.
        """
        try:
            loaded_certificates = pkcs7.load_der_pkcs7_certificates(certificates)
        except TypeError as exception:
            err_msg = (
                'Expected certificates to be a bytes object containing certificates in PEM format, '
                f'but got {type(certificates)}.'
            )
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                'Failed to load the provided certificates in PEM format. Either wrong format or data is corrupted.'
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
            TypeError: If certificates is not a bytes object.
            ValueError: If loading of one or more contained certificates failed.
        """
        try:
            loaded_certificates = pkcs7.load_pem_pkcs7_certificates(certificates)
        except TypeError as exception:
            err_msg = (
                'Expected certificates to be a bytes object containing certificates in PEM format, '
                f'but got {type(certificates)}.'
            )
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = (
                'Failed to load the provided certificates in PEM format. Either wrong format or data is corrupted.'
            )
            raise ValueError(err_msg) from exception

        return cls(loaded_certificates)

    @classmethod
    def from_pkcs12_bytes(cls, p12: bytes, password: bytes | None = None) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a PKCS#12 structure including the credential certificate.

        Args:
            p12: A PKCS#12 structure.
            password: The password to decrypt the PKCS#12 file.

        Returns:
            The corresponding CertificateCollectionSerializer.

        Raises:
            TypeError:
                If the p12 is not a bytes object, or the password is not None or a bytes object.
            ValueError:
                If parsing and loading of the PKCS#12 file failed.
        """
        loaded_p12 = load_pkcs12_bytes(p12, password)
        return cls.from_pkcs12(loaded_p12)

    @classmethod
    def from_pkcs12(cls, p12: pkcs12.PKCS12KeyAndCertificates) -> CertificateCollectionSerializer:
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
            err_msg = f'Expected p12 to be a PKCS12KeyAndCertificates object, but got {type(p12)}.'
            raise TypeError(err_msg)

        p12_certificate = p12.cert.certificate if p12.cert else None
        p12_additional_certificates = p12.additional_certs if p12.additional_certs else []

        certificates = [p12_certificate] if p12_certificate else []
        certificates.extend([cert.certificate for cert in p12_additional_certificates])

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
    def from_pkcs12_additional_certs_only(cls, p12: pkcs12.PKCS12KeyAndCertificates) -> CertificateCollectionSerializer:
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
            err_msg = f'Expected p12 to be a PKCS12KeyAndCertificates object, but got {type(p12)}.'
            raise TypeError(err_msg)

        p12_additional_certificates = p12.additional_certs if p12.additional_certs else []
        certificates = [cert.certificate for cert in p12_additional_certificates]

        return cls(certificates)

    @classmethod
    def from_bytes(cls, certificate_collection: bytes) -> CertificateCollectionSerializer:
        """Creates a CertificateCollectionSerializer from a private key in bytes in PEM or PKCS#7 (PEM | DER) format.

        Args:
            certificate_collection: The certificate collection as a bytes object in PEM or PKCS#7 (PEM | DER) format.

        Returns:
            The corresponding CertificateCollectionSerializer containing the provided certificates.

        Raises:
            TypeError: If the certificate_collection is not a bytes object.
            ValueError: If loading the certificates failed.
        """
        loaders: list[Callable[[bytes], CertificateCollectionSerializer]] = [
            cls.from_pem,
            cls.from_pkcs7_der,
            cls.from_pkcs7_pem,
        ]
        err_msg = 'Failed to load certificate. Either wrong format or corrupted certificate.'
        for loader in loaders:
            try:
                return loader(certificate_collection)
            except (TypeError, ValueError):
                pass
            except Exception as exception:
                raise ValueError(err_msg) from exception
        raise ValueError(err_msg)

    def __add__(
        self,
        other: x509.Certificate | CertificateSerializer | CertificateCollectionSerializer,
    ) -> CertificateCollectionSerializer:
        """Adds certificates to the CertificateCollectionSerializer.

        Args:
            other: The certificate or certificates to add.

        Returns:
            A new CertificateCollectionSerializer instance containing the sum of the certificates.

        Raises:
            TypeError: If other is a type that cannot be added to the CertificateCollectionSerializer.
        """
        if isinstance(other, x509.Certificate):
            return CertificateCollectionSerializer([other, *self._certificates])
        if isinstance(other, CertificateSerializer):
            if other.as_crypto() in self._certificates:
                return CertificateCollectionSerializer(self._certificates)
            return CertificateCollectionSerializer([other.as_crypto(), *self._certificates])
        if isinstance(other, CertificateCollectionSerializer):
            return CertificateCollectionSerializer(list(set(self._certificates + other._certificates)))
        err_msg = (
            'Only CertificateSerializer and CertificateCollectionSerializers can be added to a'
            'CertificateCollectionSerializer.'
        )
        raise TypeError(err_msg)

    def __len__(self) -> int:
        """Gets the number of contained certificates.

        Returns:
            Returns the number of certificates contained in this credential.
        """
        return len(self._certificates)

    def as_format(self, certificate_format: CertificateFormat) -> bytes:
        """Returns the certificate collection as bytes using the provided format.

        Args:
            certificate_format: The certificate format to use.

        Returns:
            The certificate collection as bytes using the provided format.

        Raises:
            ValueError: If the provided certificate format is not supported.
            TypeError: If an invalid type was provided or an unexpected error occurred.
        """
        try:
            if certificate_format == CertificateFormat.PEM:
                return self.as_pem()
            if certificate_format == CertificateFormat.PKCS7_DER:
                return self.as_pkcs7_der()
            if certificate_format == CertificateFormat.PKCS7_PEM:
                return self.as_pkcs7_pem()
        except ValueError:
            raise
        except Exception as exception:
            err_msg = f'Failed to get the the certificate collection in the requested format. {exception}'
            raise TypeError(err_msg) from exception

        err_msg = f'Invalid certificate format: {certificate_format}'
        raise ValueError(err_msg)

    def as_crypto(self) -> list[x509.Certificate]:
        """Gets the associated certificate collection as a list of x509.Certificate objects.

        Returns:
            List of x509.Certificate objects.
        """
        return self._certificates

    def as_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PEM format.

        Returns:
            Bytes that contain the certificate collection in PEM format.
        """
        return b''.join(self.as_pem_list())

    def as_pem_list(self) -> list[bytes]:
        """Gets the certificates as a list of PEM encoded bytes.

        Returns:
            Certificates as a list of PEM encoded bytes.
        """
        return [CertificateSerializer(certificate).as_pem() for certificate in self._certificates]

    def as_der_list(self) -> list[bytes]:
        """Gets the certificates as a list of DER encoded bytes.

        Returns:
            Certificates as a list of DER encoded bytes.
        """
        return [CertificateSerializer(certificate).as_der() for certificate in self._certificates]

    def as_certificate_serializer_list(self) -> list[CertificateSerializer]:
        """Gets the certificates as a list of CertificateSerializer objects.

        Returns:
            Certificates as a list of CertificateSerializer objects.
        """
        return [CertificateSerializer(certificate) for certificate in self._certificates]

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 PEM format.

        Returns:
            Bytes that contain the certificate collection in PKCS#7 PEM format.
        """
        if not self._certificates:
            return b''

        return pkcs7.serialize_certificates(self.as_crypto(), serialization.Encoding.PEM)

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 DER format.

        Returns:
            Bytes that contain the certificate collection in PKCS#7 DER format.
        """
        if not self._certificates:
            return b''

        return pkcs7.serialize_certificates(self.as_crypto(), serialization.Encoding.DER)


class CredentialSerializer:
    """The CredentialSerializer class provides methods for serializing and loading X.509 Credentials.

    A complete credential consists of a private key, a matching certificate and the full chain including the root ca.

    However, this object can also be used for partial credentials e.g., missing private key or only parts or no
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
        """Initializes a CredentialSerializer with the provided private key, certificate and additional certificates.

        Args:
            private_key: The private key to include in the credential.
            certificate: The certificate matching the private key.
            additional_certificates: Any further certificates, usually this will only be the certificate chain.

        Raises:
            TypeError: If an invalid type is provided for one of the arguments.
        """
        self.private_key = private_key
        self.certificate = certificate
        if additional_certificates is None:
            self.additional_certificates = []
        else:
            self.additional_certificates = additional_certificates

    @property
    def private_key(self) -> PrivateKey | None:
        """Property to get the private key object.

        Returns:
            The private key object or None.
        """
        return self._private_key

    @private_key.setter
    def private_key(self, private_key: PrivateKey | None) -> None:
        """Property to set the private key object.

        Args:
            private_key: The private key to include in the credential.

        Raises:
            TypeError: If the provided private key is not None or not a supported private key type.
        """
        if isinstance(private_key, PrivateKeySerializer):
            private_key = private_key.as_crypto()

        if not (private_key is None or isinstance(private_key, PrivateKey)):
            err_msg = f'Expected private_key to be a PrivateKey object, but got {type(private_key)}.'
            raise TypeError(err_msg)
        self._private_key = private_key

    @private_key.deleter
    def private_key(self) -> None:
        """Property to delete the private key object."""
        self._private_key = None

    def get_private_key_serializer(self) -> PrivateKeySerializer | None:
        """Gets the private key serializer."""
        if not self.private_key:
            return None
        return PrivateKeySerializer(self.private_key)

    @property
    def certificate(self) -> x509.Certificate | None:
        """Property to get the certificate object.

        Returns:
            The x509.Certificate object or None.
        """
        return self._certificate

    @certificate.setter
    def certificate(self, certificate: x509.Certificate | None) -> None:
        """Property to set the certificate object.

        Args:
            certificate: The certificate matching the private key.

        Raises:
            TypeError: If the provided certificate is not None or not a x509.Certificate object.
        """
        if not (certificate is None or isinstance(certificate, x509.Certificate)):
            err_msg = f'Expected certificate to be a x509.Certificate object, but got {type(certificate)}.'
            raise TypeError(err_msg)
        self._certificate = certificate

    @certificate.deleter
    def certificate(self) -> None:
        """Property to delete the certificate object."""
        self._certificate = None

    def get_certificate_serializer(self) -> CertificateSerializer | None:
        """Gets the certificate as a CertificateSerializer object."""
        if not self.certificate:
            return None
        return CertificateSerializer(self.certificate)

    @property
    def additional_certificates(self) -> list[x509.Certificate]:
        """Property to get the additional certificates.

        Returns:
            A list of all additional certificates as x509.Certificate objects.
        """
        return self._additional_certificates

    @additional_certificates.setter
    def additional_certificates(self, additional_certificates: list[x509.Certificate] | None) -> None:
        """Property to set the additional certificates.

        Args:
            additional_certificates: Any further certificates, usually this will only be the certificate chain.

        Raises:
            TypeError: If the provided additional_certificates is not None or not a list of x509.Certificate objects.

        """
        if additional_certificates is None:
            self._additional_certificates = []
            return

        if not isinstance(additional_certificates, list):
            err_msg = f'Expected additional_certificates to be a list, but got {type(additional_certificates)}.'
            raise TypeError(err_msg)

        for cert in additional_certificates:
            if not isinstance(cert, x509.Certificate):
                err_msg = (
                    'The provided list of certificates contains at least one object that is not a certificate object.'
                )
                raise TypeError(err_msg)

        self._additional_certificates = additional_certificates

    @additional_certificates.deleter
    def additional_certificates(self) -> None:
        """Property to delete the additional_certificates object."""
        self._additional_certificates = []

    def get_additional_certificates_serializer(self) -> CertificateCollectionSerializer | None:
        """Gets the additional certificates as a CertificateCollectionSerializer object."""
        if not self.additional_certificates:
            return None
        return CertificateCollectionSerializer(self.additional_certificates)

    @classmethod
    def from_serializers(
        cls,
        private_key_serializer: PrivateKeySerializer | None = None,
        certificate_serializer: CertificateSerializer | None = None,
        certificate_collection_serializer: CertificateCollectionSerializer | None = None,
    ) -> CredentialSerializer:
        """Creates a CredentialSerializer from the private key, certificate and certificate collection serializers.

        Args:
            private_key_serializer: PrivateKeySerializer object to use, if any.
            certificate_serializer: CertificateSerializer object to use, if any.
            certificate_collection_serializer: CertificateCollectionSerializer object to use, if any.

        Returns:
            The created CredentialSerializer.

        Raises:
            TypeError: If extracting the private key, certificate and certificate collection serializers failed.
        """
        try:
            private_key = private_key_serializer.as_crypto() if private_key_serializer else None
            certificate = certificate_serializer.as_crypto() if certificate_serializer else None
            additional_certificates = (
                certificate_collection_serializer.as_crypto() if certificate_collection_serializer else []
            )
        except Exception as exception:
            err_msg = 'Failed to extract the private key, certificate and certificate collection serializers.'
            raise TypeError(err_msg) from exception

        return cls(private_key=private_key, certificate=certificate, additional_certificates=additional_certificates)

    @classmethod
    def from_pkcs12_bytes(cls, p12: bytes, password: bytes | None = None) -> CredentialSerializer:
        """Creates a CredentialSerializer from a PKCS#12 structure.

        Args:
            p12: A PKCS#12 structure.
            password: The password to decrypt the PKCS#12 file.

        Returns:
            The corresponding CredentialSerializer.

        Raises:
            TypeError: If the p12 is not a bytes object or the password is not None or a bytes object.
            ValueError: If parsing and loading of the PKCS#12 file failed.
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
        """
        if not isinstance(p12, pkcs12.PKCS12KeyAndCertificates):
            err_msg = f'Expected p12 to be a PKCS12KeyAndCertificates object, but got {type(p12)}.'
            raise TypeError(err_msg)

        certificate = p12.cert.certificate if p12.cert else None
        private_key = p12.key
        p12_additional_certificates = p12.additional_certs if p12.additional_certs else []
        additional_certificates = [cert.certificate for cert in p12_additional_certificates]

        if not isinstance(private_key, typing.get_args(PrivateKey)):
            err_msg = f'p12.key contains is a key type that is not supported: {type(private_key)}.'
            raise TypeError(err_msg)

        return cls(private_key, certificate, additional_certificates)

    def as_pkcs12(self, password: None | bytes = None, friendly_name: bytes = b'') -> bytes:
        """Gets the associated private key as bytes in a PKCS#12 structure.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            Bytes object that contains the private key in a PKCS#12 structure.

        Raises:
            ValueError:
                If the CredentialSerializer does not contain at least one of the following:
                private key, certificate or certificate collection or getting the BestAvailableEncryption failed.
        """
        if self.private_key is None and self.certificate is None and not self.additional_certificates:
            err_msg = (
                'Cannot create a PKCS#12 structure without at least on of the following:'
                'private key, certificate or certificate collection.'
            )
            raise ValueError(err_msg)
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self.private_key,
            cert=self.certificate,
            cas=self.additional_certificates,
            encryption_algorithm=get_encryption_algorithm(password),
        )

    def get_full_chain_as_crypto(self) -> list[x509.Certificate]:
        """Gets the full chain as a list of x509.Certificate objects.

        Returns:
            A list of x509.Certificate objects representing
            the full chain with the first element being the credential certificate.
        """
        if self.certificate:
            return [
                self.certificate,
                *self.additional_certificates,
            ]

        return [
            *self.additional_certificates,
        ]

    def get_full_chain_as_serializer(self) -> CertificateCollectionSerializer:
        """Gets the full chain as a CertificateCollectionSerializer object.

        Returns:
            A CertificateCollectionSerializer object containing
            the full chain with the first element being the credential certificate.
        """
        return CertificateCollectionSerializer(self.get_full_chain_as_crypto())
