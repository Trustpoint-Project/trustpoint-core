"""This module contains serializers for certificates and keys."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, pkcs12

from trustpoint_core.types import PrivateKey, PublicKey


if TYPE_CHECKING:
    from cryptography.hazmat.primitives.serialization import KeySerializationEncryption


class PublicKeySerializer:
    """The PublicKeySerializer class provides methods for serializing and loading a public key."""

    _public_key: PublicKey
    _pem: bytes | None = None
    _der: bytes | None = None

    def __init__(self, public_key: PublicKey) -> None:
        """Initializes a PublicKeySerializer with the provided public key object.

        Args:
            public_key: The public key object to be serialized.
        """
        if not isinstance(public_key, PublicKey):
            raise TypeError("Public key must be of type 'PublicKey'")
        self._public_key = public_key

    @classmethod
    def from_der(cls, public_key: bytes) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a DER encoded public key.

        Args:
            public_key: The public key as bytes object in DER format.

        Returns:
            The corresponding PublicKeySerializer containing the provided key.

        Raises:
            TypeError: If public_key is not a bytes object.
            ValueError: If loading the public key failed.
        """
        try:
            return cls(serialization.load_der_public_key(public_key))
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = 'Algorithm found in public key is not supported.'
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = f'Expected public_key to be a bytes-like object, got {type(public_key)}.'
            raise TypeError(err_msg) from exception
        except Exception as exception:
            err_msg = 'Failed to load public key in DER format. Either wrong format or corrupted public key.'
            raise ValueError(err_msg) from exception

    @classmethod
    def from_pem(cls, public_key: bytes) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a PEM encoded public key.

        Args:
            public_key: The public key as bytes object in PEM format.

        Returns:
            The corresponding PublicKeySerializer containing the provided key.

        Raises:
            TypeError: If public_key is not a bytes object.
            ValueError: If loading the public key failed.
        """
        try:
            return cls(serialization.load_pem_public_key(public_key))
        except crypto_exceptions.UnsupportedAlgorithm as exception:
            err_msg = 'The algorithm of the provided public key is not supported.'
            raise ValueError(err_msg) from exception
        except TypeError as exception:
            err_msg = f'Expected public_key to be a bytes-like object, got {type(public_key)}.'
            raise TypeError(err_msg) from exception
        except ValueError as exception:
            err_msg = 'Failed to load public key in PEM format. Either wrong format or corrupted public key.'
            raise ValueError(err_msg) from exception

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeySerializer:
        """Creates a PublicKeySerializer from a private key object.

        Args:
            private_key: The private key object.

        Returns:
            The corresponding PublicKeySerializer containing the public key contained in the provided private key.

        Raises:
            TypeError: If private key is not a private key object.
        """
        if not isinstance(private_key, PrivateKey):
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
            TypeError: If private key is not a private key object.
        """
        if not isinstance(certificate, x509.Certificate):
            err_msg = f'Expected a certificate object, but got {type(certificate)}.'
            raise TypeError(err_msg)

        return cls(certificate.public_key())

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
        """
        self._private_key = private_key

    def from_pem(self, private_key: bytes, password: bytes | None ):
        pass

    def from_der(self):
        pass

    def from_pkcs12(self):
        pass

    def _from_bytes(
        self, private_key: bytes, password: None | bytes = None
    ) -> PrivateKey:
        try:
            return self._load_pem_private_key(private_key, password)
        except ValueError:
            pass

        try:
            return self._load_der_private_key(private_key, password)
        except ValueError:
            pass

        try:
            return self._load_pkcs12_private_key(private_key, password)
        except ValueError:
            pass

        err_msg = "Failed to load private key. May be an incorrect password, malformed data or an unsupported format."
        raise ValueError(err_msg)

    def _from_string(
        self, private_key: str, password: None | bytes = None
    ) -> PrivateKey:
        return self._from_bytes(private_key.encode(), password)

    def serialize(self, password: None | bytes = None) -> bytes:
        """Default serialization method that gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self.as_pkcs8_pem(password=password)

    def as_pkcs1_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#1 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs1_pem(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#1 PEM format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#1 PEM format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs8_der(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs8_pem(self, password: None | bytes = None) -> bytes:
        """Gets the associated private key as bytes in PKCS#8 DER format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.

        Returns:
            bytes: Bytes that contains the private key in PKCS#8 DER format.
        """
        return self._private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pkcs12(
        self, password: None | bytes = None, friendly_name: bytes = b""
    ) -> bytes:
        """Gets the associated private key as bytes in PKCS#12 format.

        Args:
            password:
                Password if the private key shall be encrypted, None otherwise.
                Empty bytes will be interpreted as None.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            bytes: Bytes that contains the private key in PKCS#12 format.
        """
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self._private_key,
            cert=None,
            cas=None,
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_crypto(self) -> PrivateKey:
        """Gets the associated private key as PrivateKey instance.

        Returns:
            PrivateKey: The associated private key as PrivateKey instance.
        """
        return self._private_key

    @property
    def public_key_serializer(self) -> PublicKeySerializer:
        """Gets the PublicKeySerializer instance of the associated private key.

        Returns:
            PublicKeySerializer: PublicKeySerializer instance of the associated private key.
        """
        return PublicKeySerializer(self._private_key.public_key())

    @staticmethod
    def _get_encryption_algorithm(
        password: None | bytes = None,
    ) -> serialization.KeySerializationEncryption:
        if password:
            return serialization.BestAvailableEncryption(password)
        return serialization.NoEncryption()

    @staticmethod
    def _load_pem_private_key(
        private_key: bytes, password: None | bytes = None
    ) -> PrivateKey:
        try:
            return serialization.load_pem_private_key(private_key, password)
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_der_private_key(
        private_key: bytes, password: None | bytes = None
    ) -> PrivateKey:
        try:
            return serialization.load_der_private_key(private_key, password)
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_pkcs12_private_key(
        p12_data: bytes, password: None | bytes = None
    ) -> PrivateKey:
        try:
            return pkcs12.load_pkcs12(p12_data, password).key
        except Exception as exception:
            raise ValueError from exception


class CertificateSerializer:
    """The CertificateSerializer class provides methods for serializing and loading a certificate.

    Warnings:
        The CertificateSerializer class does not evaluate or validate any contents of the certificate.
    """

    _certificate: x509.Certificate
    _public_key_serializer: None | PublicKeySerializer = None

    def __init__(
        self, certificate: bytes | str | x509.Certificate | CertificateSerializer
    ) -> None:
        """Inits the CertificateSerializer class.

        Args:
            certificate: The certificate to serialize.

        Raises:
            TypeError: If the certificate is not a x509.Certificate instance.
            ValueError: If the certificate failed to deserialize.
        """
        if isinstance(certificate, bytes):
            self._certificate = self._from_bytes(certificate)
        elif isinstance(certificate, str):
            self._certificate = self._from_string(certificate)
        elif isinstance(certificate, x509.Certificate):
            self._certificate = certificate
        elif isinstance(certificate, CertificateSerializer):
            self._certificate = certificate.as_crypto()
        else:
            err_msg = (
                "Certificate must be of type bytes, str, x509.Certificate or CertificateSerializer, "
                f"but got {type(certificate)}."
            )
            raise TypeError(err_msg)

    def _from_bytes(self, certificate_data: bytes) -> x509.Certificate:
        try:
            return self._load_pem_certificate(certificate_data)
        except ValueError:
            pass

        try:
            return self._load_der_certificate(certificate_data)
        except ValueError:
            pass

        err_msg = "Failed to load certificate. May be malformed or not in a DER or PEM format."
        raise ValueError(err_msg)

    def _from_string(self, certificate_data: str) -> x509.Certificate:
        return self._from_bytes(certificate_data.encode())

    def serialize(self) -> bytes:
        """Default serialization method that returns the certificate as PEM encoded bytes.

        Returns:
            bytes: Bytes that contains the certificate in PEM format.
        """
        return self.as_pem()

    def as_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PEM format.

        Returns:
            bytes: Bytes that contains the certificate in PEM format.
        """
        return self._certificate.public_bytes(encoding=serialization.Encoding.PEM)

    def as_der(self) -> bytes:
        """Gets the associated certificate as bytes in DER format.

        Returns:
            bytes: Bytes that contains the certificate in DER format.
        """
        return self._certificate.public_bytes(encoding=serialization.Encoding.DER)

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 PEM format.

        Returns:
            bytes: Bytes that contains the certificate in PKCS#7 PEM format.
        """
        return pkcs7.serialize_certificates(
            [self._certificate], serialization.Encoding.PEM
        )

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate as bytes in PKCS#7 DER format.

        Returns:
            bytes: Bytes that contains the certificate in PKCS#7 DER format.
        """
        return pkcs7.serialize_certificates(
            [self._certificate], serialization.Encoding.DER
        )

    def as_crypto(self) -> x509.Certificate:
        """Gets the associated certificate as x509.Certificate instance.

        Returns:
            x509.Certificate: The associated certificate as x509.Certificate instance.
        """
        return self._certificate

    @property
    def public_key_serializer(self) -> PublicKeySerializer:
        """Property to get the corresponding PublicKeySerializer object (lazy loading).

        Returns:
            PublicKeySerializer: The corresponding PublicKeySerializer object.
        """
        if self._public_key_serializer is None:
            self._public_key_serializer = PublicKeySerializer(
                self._certificate.public_key()
            )
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


class CertificateCollectionSerializer(Serializer):
    """The CertificateCollectionSerializer class provides methods for serializing and loading certificate collections.

    Certificate collections are lists of single certificates. The order will be preserved. Usually these collections
    will either be a certificate chain or a trust store.

    Warnings:
        The CertificateCollectionSerializer class does not evaluate or validate any contents of the certificate
        collection, i.e. no certificate chains are validated.
    """

    _certificate_collection: list[CertificateSerializer]

    def __init__(
        self,
        certificate_collection: bytes
        | str
        | CertificateCollectionSerializer
        | list[bytes]
        | list[str]
        | list[x509.Certificate]
        | list[CertificateSerializer],
    ) -> None:
        """Inits the CertificateCollectionSerializer class.

        Args:
            certificate_collection: A collection of certificates.

        Raises:
            TypeError: If certificate_collection is not a list of x509.Certificates.
            ValueError: If the certificate_collection failed to deserialize.
        """
        if isinstance(certificate_collection, bytes):
            self._certificate_collection = self._from_bytes(certificate_collection)
        elif isinstance(certificate_collection, str):
            self._certificate_collection = self._from_string(certificate_collection)
        elif isinstance(certificate_collection, list):
            self._certificate_collection = [
                CertificateSerializer(certificate)
                for certificate in certificate_collection.copy()
            ]
        elif isinstance(certificate_collection, CertificateCollectionSerializer):
            self._certificate_collection = (
                certificate_collection.as_certificate_serializer_list().copy()
            )
        else:
            err_msg = (
                "Expected one of the types: "
                "bytes | str | list[bytes | str | x509.Certificate | CertificateSerializer], "
                f"but got {type(certificate_collection)}"
            )
            raise TypeError(err_msg)

    def _from_bytes(
        self, certificate_collection_data: bytes
    ) -> list[CertificateSerializer]:
        try:
            return [
                CertificateSerializer(certificate)
                for certificate in self._load_pem(certificate_collection_data)
            ]
        except ValueError:
            pass

        try:
            return [
                CertificateSerializer(certificate)
                for certificate in self._load_pkcs7_pem(certificate_collection_data)
            ]
        except ValueError:
            pass

        try:
            return [
                CertificateSerializer(certificate)
                for certificate in self._load_pkcs7_der(certificate_collection_data)
            ]
        except ValueError:
            pass

        err_msg = (
            "Failed to load certificate collection. "
            "May be an malformed data or an unsupported format."
        )
        raise ValueError(err_msg)

    def _from_string(
        self, certificate_collection_data: str
    ) -> list[CertificateSerializer]:
        return self._from_bytes(certificate_collection_data.encode())

    def __len__(self) -> int:
        """Returns the number of certificates contained in this credential."""
        return len(self._certificate_collection)

    def serialize(self) -> bytes:
        """Default serialization method that returns the certificate collection as PEM encoded bytes.

        Returns:
            bytes: Bytes that contains certificate collection in PEM format.
        """
        return self.as_pem()

    def as_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PEM format.

        Returns:
            bytes: Bytes that contains certificate collection in PEM format.
        """
        return b"".join(
            [certificate.as_pem() for certificate in self._certificate_collection]
        )

    def as_crypto(self) -> list[x509.Certificate]:
        """Gets the associated certificate collection as list of x509.Certificate instances.

        Shorthand for as_crypto_list().

        Returns:
            list[x509.Certificate]: List of x509.Certificate instances.
        """
        return self.as_crypto_list()

    def as_crypto_list(self) -> list[x509.Certificate]:
        """Gets the associated certificate collection as list of x509.Certificate instances.

        Returns:
            list[x509.Certificate]: List of x509.Certificate instances.
        """
        return [cert.as_crypto() for cert in self._certificate_collection]

    def as_pem_list(self) -> list[bytes]:
        """Gets the certificates as list of PEM encoded bytes.

        Returns:
            list[bytes]: Certificates as list of PEM encoded bytes.
        """
        return [certificate.as_pem() for certificate in self._certificate_collection]

    def as_der_list(self) -> list[bytes]:
        """Gets the certificates as list of DER encoded bytes.

        Returns:
            list[bytes]: Certificates as list of DER encoded bytes.
        """
        return [certificate.as_der() for certificate in self._certificate_collection]

    def as_certificate_serializer_list(self) -> list[CertificateSerializer]:
        """Gets the certificates as list of CertificateSerializer instances.

        Returns:
            list[bytes]: Certificates as list of CertificateSerializer instances.
        """
        return self._certificate_collection

    def as_pkcs7_pem(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 PEM format.

        Returns:
            bytes: Bytes that contains certificate collection in PKCS#7 PEM format.
        """
        return pkcs7.serialize_certificates(
            self.as_crypto_list(), serialization.Encoding.PEM
        )

    def as_pkcs7_der(self) -> bytes:
        """Gets the associated certificate collection as bytes in PKCS#7 DER format.

        Returns:
            bytes: Bytes that contains certificate collection in PKCS#7 DER format.
        """
        return pkcs7.serialize_certificates(
            self.as_crypto_list(), serialization.Encoding.DER
        )

    def __iter__(self) -> typing.Iterator[CertificateSerializer]:
        """Gets an iterator over the CertificateCollectionSerializer instances.

        Returns:
            typing.Iterator[CertificateSerializer]: Iterator over the CertificateCollectionSerializer instances.
        """
        return iter(self._certificate_collection)

    def certificate_serializer_iterator(self) -> typing.Iterator[CertificateSerializer]:
        """Gets an iterator over the CertificateCollectionSerializer instances.

        Returns:
            typing.Iterator[CertificateSerializer]: Iterator over the CertificateCollectionSerializer instances.
        """
        return self.__iter__()

    def crypto_iterator(self) -> typing.Iterator[x509.Certificate]:
        """Gets an iterator over the x509.Certificate instances.

        Returns:
            typing.Iterator[CertificateSerializer]: Iterator over the x509.Certificate instances.
        """
        return iter(self.as_crypto_list())

    def pem_iterator(self) -> typing.Iterator[bytes]:
        """Gets an iterator over the associated certificates as list of PEM encoded bytes.

        Returns:
            typing.Iterator[bytes]: Iterator over the associated certificates as list of PEM encoded bytes.
        """
        return iter(self.as_pem_list())

    def der_iterator(self) -> typing.Iterator[bytes]:
        """Gets an iterator over the associated certificates as list of DER encoded bytes.

        Returns:
            typing.Iterator[bytes]: Iterator over the associated certificates as list of DER encoded bytes.
        """
        return iter(self.as_der_list())

    def append(
        self, certificate: bytes | str | x509.Certificate | CertificateSerializer
    ) -> None:
        """Appends a single certificate to the collection.

        Args:
            certificate: The certificate to append.
        """
        self._certificate_collection.append(CertificateSerializer(certificate))

    def extend(
        self,
        certificates: bytes
        | str
        | CertificateCollectionSerializer
        | list[bytes]
        | list[str]
        | list[x509.Certificate]
        | list[CertificateSerializer],
    ) -> None:
        """Extends the collection by the passed certificates.

        Args:
            certificates: The certificates to extend the collection with.
        """
        new_certificate_collection = CertificateCollectionSerializer(certificates)
        self._certificate_collection.extend(
            new_certificate_collection.as_certificate_serializer_list()
        )

    @staticmethod
    def _load_pem(pem_data: bytes) -> list[x509.Certificate]:
        try:
            return x509.load_pem_x509_certificates(pem_data)
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_pkcs7_pem(p7_data: bytes) -> list[x509.Certificate]:
        try:
            return pkcs7.load_pem_pkcs7_certificates(p7_data)
        except Exception as exception:
            raise ValueError from exception

    @staticmethod
    def _load_pkcs7_der(p7_data: bytes) -> list[x509.Certificate]:
        try:
            return pkcs7.load_der_pkcs7_certificates(p7_data)
        except Exception as exception:
            raise ValueError from exception


class CredentialSerializer(Serializer):
    """The CredentialSerializer class provides methods for serializing and loading X.509 Credentials.

    These Credentials consist of one private key and the corresponding certificate. Further certificates, like
    the corresponding certificate chain may also be included.

    Warnings:
        The CredentialSerializer class does not evaluate or validate any contents of the credential,
        i.e. neither the certificate chain nor if the private key matches the certificate is validated.
    """

    _credential_private_key: PrivateKeySerializer
    _credential_certificate: CertificateSerializer
    _additional_certificates: None | CertificateCollectionSerializer = None

    _TUPLE_LEN_WITHOUT_ADDITIONAL_CERTIFICATES = 2
    _TUPLE_LEN_WITH_ADDITIONAL_CERTIFICATES = 3

    class PrivateKeyFormat(enum.Enum):
        """Supported formats for private keys."""

        PKCS1 = "pkcs1"
        PKCS8 = "pkcs8"

    class FileFormat(enum.Enum):
        """Supported credential file formats."""

        PKCS12 = "PKCS12"
        PEM_ZIP = "PEM_ZIP"
        PEM_TAR_GZ = "PEM_TAR_GZ"

    def __init__(
        self,
        credential: bytes
        | pkcs12.PKCS12KeyAndCertificates
        | CredentialSerializer
        | tuple[PrivateKeyType, CertificateType]
        | tuple[
            PrivateKeyType,
            CertificateType,
            None | list[CertificateType] | CertificateCollectionSerializer,
        ],
        password: None | bytes = None,
    ) -> None:
        """Inits the CredentialSerializer class.

        Either a credential or both credential_private_key and credential_certificate must be provided.

        Args:
            credential:
                A PKCS#12 credential as bytes, pkcs12.PKCS12KeyAndCertificates, a CredentialSerializer instance or a
                tuple of the credential_private_key, credential_certificate and optionally additional_certificates.
            password: The password for either the credential or the credential_private_key, if any.

        Raises:
            TypeError: If an invalid argument type was provided for any of the parameters.
            ValueError: If the credential failed to deserialize.
        """
        if password == b"":
            password = None

        if isinstance(credential, bytes):
            cred_priv_key, cred_cert, add_certs = self._from_bytes_pkcs12(
                credential, password
            )
            self._credential_private_key = cred_priv_key
            self._credential_certificate = cred_cert
            self._additional_certificates = add_certs
        elif isinstance(credential, pkcs12.PKCS12KeyAndCertificates):
            cred_priv_key, cred_cert, add_certs = self._from_crypto_pkcs12(credential)
            self._credential_private_key = cred_priv_key
            self._credential_certificate = cred_cert
            self._additional_certificates = add_certs
        elif isinstance(credential, CredentialSerializer):
            self._credential_private_key = credential.credential_private_key
            self._credential_certificate = credential.credential_certificate
            self._additional_certificates = credential.additional_certificates
        elif isinstance(credential, tuple):
            if len(credential) == self._TUPLE_LEN_WITHOUT_ADDITIONAL_CERTIFICATES:
                credential_private_key, credential_certificate = credential
                additional_certificates = None
            elif len(credential) == self._TUPLE_LEN_WITH_ADDITIONAL_CERTIFICATES:
                (
                    credential_private_key,
                    credential_certificate,
                    additional_certificates,
                ) = credential
            else:
                err_msg = (
                    f"Got a tuple of length {len(credential)}, but expected a tuple containing the "
                    f"credential private key, credential certificate and optionally additional certificates. "
                    f"Thus expected a tuple of length 2 or 3."
                )
                raise TypeError(err_msg)

            if (
                credential_private_key is not None
                and credential_certificate is not None
            ):
                self._credential_private_key = PrivateKeySerializer(
                    credential_private_key
                )
                self._credential_certificate = CertificateSerializer(
                    credential_certificate
                )
                if additional_certificates is not None:
                    self._additional_certificates = CertificateCollectionSerializer(
                        additional_certificates
                    )
            else:
                err_msg = (
                    "To instantiate a CredentialSerializer from separate objects, at least the credential private key"
                    "and the credential certificate must be provided."
                )
                raise TypeError(err_msg)
        else:
            err_msg = (
                "Credential must be of type bytes, pkcs12.PKCS12KeyAndCertificates, CredentialSerializer or a tuple"
                "of the credential private key, credential certificate and optional additional certificates, "
                f"but got {type(credential)}."
            )
            raise TypeError(err_msg)

    @staticmethod
    def _from_crypto_pkcs12(
        p12: pkcs12.PKCS12KeyAndCertificates,
    ) -> tuple[
        PrivateKeySerializer, CertificateSerializer, CertificateCollectionSerializer
    ]:
        additional_certificates = [
            CertificateSerializer(certificate.certificate)
            for certificate in p12.additional_certs
        ]
        return (
            PrivateKeySerializer(p12.key),
            CertificateSerializer(p12.cert.certificate),
            CertificateCollectionSerializer(additional_certificates),
        )

    @classmethod
    def _from_bytes_pkcs12(
        cls, credential_data: bytes, password: None | bytes = None
    ) -> tuple[
        PrivateKeySerializer, CertificateSerializer, CertificateCollectionSerializer
    ]:
        try:
            return cls._from_crypto_pkcs12(
                pkcs12.load_pkcs12(credential_data, password)
            )
        except ValueError as exception:
            err_msg = "Failed to load credential. May be an incorrect password or malformed data."
            raise ValueError(err_msg) from exception

    def serialize(
        self, password: None | bytes = None, friendly_name: bytes = b""
    ) -> bytes:
        """Default serialization method that returns the credential as PKCS#12 bytes.

        Returns:
            bytes: Bytes that contains the credential in PKCS#12 format.
        """
        return self.as_pkcs12(password, friendly_name)

    def as_pkcs12(
        self, password: None | bytes = None, friendly_name: bytes = b""
    ) -> bytes:
        """Gets the credential as bytes in PKCS#12 format.

        Args:
            password: Password if the credential shall be encrypted, None otherwise.
            friendly_name: The friendly_name to set in the PKCS#12 structure.

        Returns:
            bytes: Bytes that contains the credential in PKCS#12 format.
        """
        return pkcs12.serialize_key_and_certificates(
            name=friendly_name,
            key=self._credential_private_key.as_crypto(),
            cert=self._credential_certificate.as_crypto(),
            cas=self._additional_certificates.as_crypto(),
            encryption_algorithm=self._get_encryption_algorithm(password),
        )

    def as_pem_zip(self, password: None | bytes = None) -> bytes:
        return Archiver.archive_zip(
            {
                "private_key.pem": self.credential_private_key.as_pkcs8_pem(
                    password=password
                ),
                "certificate.pem": self.credential_certificate.as_pem(),
                "certificate_chain.pem": self.additional_certificates.as_pem(),
            }
        )

    def as_pem_tar_gz(self, password: None | bytes = None) -> bytes:
        return Archiver.archive_tar_gz(
            {
                "private_key.pem": self.credential_private_key.as_pkcs8_pem(
                    password=password
                ),
                "certificate.pem": self.credential_certificate.as_pem(),
                "certificate_chain.pem": self.additional_certificates.as_pem(),
            }
        )

    def __len__(self) -> int:
        """Returns the number of certificates contained in this credential."""
        if self._additional_certificates is None:
            return 1

        return len(self._additional_certificates) + 1

    def get_as_separate_pem_files(
        self,
        private_key_format: PrivateKeyFormat = PrivateKeyFormat.PKCS8,
        password: None | bytes = None,
    ) -> tuple[bytes, bytes, bytes | None]:
        """Gets the credential as separate bytes in PEM format with the private key in the specified format.

        Note:
            If a password is provided, the best available encryption is used, specified by the python cryptography
            package.

            A tuple of the following three values (bytes) is returned:

            - private key
            - credential certificate
            - additional certificates

        Args:
            password: A password used to encrypt the private key.
            private_key_format: Enum CredentialSerializer.PrivateKeyFormat to specify the format of the private key.

        Returns:
            (bytes, bytes, bytes | None):
                private key as PKCS#1 PEM bytes,
                credential certificate as PEM bytes,
                additional certificates as PEM bytes.
        """
        if private_key_format == self.PrivateKeyFormat.PKCS1:
            private_key_pem = self._credential_private_key.as_pkcs1_der(password)
        elif private_key_format == self.PrivateKeyFormat.PKCS8:
            private_key_pem = self._credential_private_key.as_pkcs8_pem(password)
        else:
            err_msg = (
                f"Provided private_key_format {private_key_format} is not supported."
            )
            raise ValueError(err_msg)
        return (
            private_key_pem,
            self.credential_certificate.as_pem(),
            self.additional_certificates.as_pem()
            if self.additional_certificates
            else None,
        )

    @property
    def credential_private_key(self) -> PrivateKeySerializer:
        """Returns the credential private key as PrivateKeySerializer instance."""
        return self._credential_private_key

    @credential_private_key.setter
    def credential_private_key(
        self, credential_private_key: PrivateKeySerializer
    ) -> None:
        """Sets the credential private key."""
        self._credential_private_key = credential_private_key

    @property
    def credential_certificate(self) -> CertificateSerializer:
        """Returns the credential certificate as CertificateSerializer instance."""
        return self._credential_certificate

    @credential_certificate.setter
    def credential_certificate(
        self, credential_certificate: CertificateSerializer
    ) -> None:
        """Sets the credential certificate."""
        self._credential_certificate = credential_certificate

    @property
    def additional_certificates(self) -> CertificateCollectionSerializer:
        """Returns the additional certificates as CertificateCollectionSerializer instance."""
        return self._additional_certificates

    @additional_certificates.setter
    def additional_certificates(
        self, additional_certificates: CertificateCollectionSerializer
    ) -> None:
        """Sets the additional certificates."""
        self._additional_certificates = additional_certificates

    @property
    def all_certificates(self) -> CertificateCollectionSerializer:
        """Returns both the credential and additional certificates as CertificateCollectionSerializer instance."""
        if self._additional_certificates is None:
            return CertificateCollectionSerializer([self._credential_certificate])

        new_collection = CertificateCollectionSerializer(self._additional_certificates)
        new_collection.append(self._credential_certificate)
        return new_collection

    @staticmethod
    def _get_encryption_algorithm(password: None | bytes) -> KeySerializationEncryption:
        if password:
            return serialization.BestAvailableEncryption(password)
        return serialization.NoEncryption()

    @staticmethod
    def _load_pkcs12(
        p12_data: bytes, password: None | bytes = None
    ) -> (PrivateKey, x509.Certificate, list[x509.Certificate]):
        try:
            return pkcs12.load_key_and_certificates(p12_data, password)
        except Exception as exception:
            raise ValueError from exception
