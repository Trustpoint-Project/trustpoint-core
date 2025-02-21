# type: ignore
"""X.509 utility classes and methods."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature

from .serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
)

if TYPE_CHECKING:
    from cryptography import x509


class CertificateChainExtractor:
    """Extracts the certificate chain corresponding to a given certificate form a set of certificates."""

    _certificate: x509.Certificate

    # The certificate collection passed into the constructor.
    _initial_certificate_collection: list[x509.Certificate]

    # The certificate collection without any duplicates.
    _certificate_collection: list[x509.Certificate]

    # The extracted certificate chain, excl. the certificate for which the certificate chain was extracted
    _certificate_chain: list[x509.Certificate]

    def __init__(
        self,
        certificate_serializer: CertificateSerializer,
        certificate_collection_serializer: CertificateCollectionSerializer,
    ) -> None:
        """Initializes a CertificateChainExtractor instance.

        Args:
            certificate_serializer: Contains the certificate for which the certificate chain should be extracted.
            certificate_collection_serializer: The set of certificates to extract the certificate chain from.
        """
        self._certificate = certificate_serializer.as_crypto()
        self._initial_certificate_collection = (
            certificate_collection_serializer.as_crypto()
        )

        if self._initial_certificate_collection:
            self._certificate_collection = list(
                dict.fromkeys(self._initial_certificate_collection)
            )
        else:
            self._certificate_collection = []

        self._extract_certificate_chain()

    @staticmethod
    def _verify_directly_issued_by(
        certificate: x509.Certificate, potential_issuer: x509.Certificate
    ) -> bool:
        try:
            certificate.verify_directly_issued_by(potential_issuer)
        except (ValueError, TypeError, InvalidSignature):
            return False
        else:
            return True

    def _extract_certificate_chain(self) -> None:
        if self.certificate_collection_size == 0:
            self._certificate_chain = []
            return

        certificate_chain = []
        current_certificate = self._certificate

        while True:
            issuers = [
                certificate
                for certificate in self._certificate_collection
                if self._verify_directly_issued_by(
                    certificate=current_certificate, potential_issuer=certificate
                )
            ]

            if len(issuers) == 0:
                break
            if len(issuers) == 1:
                if current_certificate == issuers[0]:
                    break
                certificate_chain.append(issuers[0])
                current_certificate = issuers[0]
                continue
            err_msg = "Found multiple valid certificate chains."
            raise ValueError(err_msg)

        self._certificate_chain = certificate_chain

    @property
    def certificate(self) -> x509.Certificate:
        """Gets the certificate."""
        return self._certificate

    @property
    def certificate_serializer(self) -> CertificateSerializer:
        """Gets the certificate."""
        return CertificateSerializer(self.certificate)

    @property
    def initial_certificate_collection(self) -> list[x509.Certificate]:
        """Gets the set of certificates."""
        return self._initial_certificate_collection

    @property
    def initial_certificate_collection_serializer(
        self,
    ) -> CertificateCollectionSerializer:
        """Gets the set of certificates."""
        return CertificateCollectionSerializer(self.initial_certificate_collection)

    @property
    def initial_certificate_collection_size(self) -> int:
        """Gets the size of the set of certificates"""
        return len(self.initial_certificate_collection)

    @property
    def certificate_collection(self) -> list[x509.Certificate]:
        """Gets the set of certificates without any duplicates."""
        return self._certificate_collection

    @property
    def certificate_collection_serializer(self) -> CertificateCollectionSerializer:
        """Gets the set of certificates without any duplicates."""
        return CertificateCollectionSerializer(self.certificate_collection)

    @property
    def certificate_collection_size(self) -> int:
        """Gets the size of the set of certificates without any duplicates."""
        return len(self.certificate_collection)

    @property
    def certificate_chain(self) -> list[x509.Certificate]:
        """Gets the extracted certificate chain."""
        return self._certificate_chain

    @property
    def certificate_chain_serializer(self) -> CertificateCollectionSerializer:
        """Gets the extracted certificate chain."""
        return CertificateCollectionSerializer(self.certificate_chain)

    @property
    def certificate_chain_size(self) -> int:
        """Gets the size of the set of the extracted certificate chain without any duplicates."""
        return len(self.certificate_chain)

    @property
    def certificate_chain_including_certificate(self) -> list[x509.Certificate]:
        """Gets the extracted certificate chain including the certificate corresponding to the chain."""
        return [self._certificate, *self._certificate_chain]

    @property
    def certificate_chain_including_certificate_serializer(
        self,
    ) -> CertificateCollectionSerializer:
        """Gets the extracted certificate chain including the certificate corresponding to the chain."""
        return CertificateCollectionSerializer(
            self.certificate_chain_including_certificate
        )
