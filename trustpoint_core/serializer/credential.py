# type: ignore
"""The credential module provides Serializer classes for X.509 Credential serialization."""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from trustpoint_core.file_builder.archiver import Archiver

from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
    Serializer,
)

if TYPE_CHECKING:
    from typing import Union
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import KeySerializationEncryption
    from trustpoint_core.types import PrivateKey

    CertificateType = Union[bytes, str, x509.Certificate, CertificateSerializer]
    PrivateKeyType = Union[bytes | str | PrivateKey | PrivateKeySerializer]


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
