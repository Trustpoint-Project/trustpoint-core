"""This module contains test for serializer."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives._serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12KeyAndCertificates
from cryptography.x509 import Certificate

from trustpoint_core import serializer
from trustpoint_core.serializer import (
    CertificateCollectionSerializer,
    CertificateSerializer,
    PrivateKeySerializer,
    PublicKeySerializer,
)


@pytest.fixture
def generate_private_key() -> RSAPrivateKey:
    """Fixture to generate private key for testing.

    Returns: RSAPrivateKey
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def generate_public_key(generate_private_key: RSAPrivateKey) -> RSAPublicKey:
    """This fixture generates public key for testing.

    Args:
        generate_private_key: RsaPrivateKey.

    Returns:
        it returns a RSAPublicKey.
    """
    return generate_private_key.public_key()


@pytest.fixture
def generate_certificate() -> Certificate:
    """Fixture to generate a self-signed certificate for testing.

    Returns:
        Certificate
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test Certificate')])

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(private_key, algorithm=hashes.SHA256())
    )


@pytest.fixture
def generate_certificates() -> list[Certificate]:
    """Fixture to generate multiple self-signed certificates for testing.

    Returns:
        it returns List of certificates.
    """
    certificates = []
    for i in range(3):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, f'Test Certificate {i}')])

        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
            .sign(private_key, algorithm=hashes.SHA256())
        )

        certificates.append(certificate)

    return certificates


@pytest.fixture
def generate_pkcs12_data() -> tuple[bytes, bytes]:
    """Fixture to generate pkcs12 data for testing.

    Returns:
        It returns a tuple of pkc12 data and its password both in bytes format.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    issuer = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'GR'),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, 'Baden-Württemberg'),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, 'Freiburg im Breisgau'),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'Campus Schwarzwald'),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, 'schwarzwald-campus.example.com'),
        ]
    )

    subject = issuer

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    password = b'testing321'
    p12_data = pkcs12.serialize_key_and_certificates(
        name=b'mykey',
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(password),
    )
    return p12_data, password


def test_load_pkc12(generate_pkcs12_data: tuple[bytes, bytes]) -> None:
    """This checks if function loads pkcs12 data, when input is correct.

    Args:
        generate_pkcs12_data: contains pkcs12 data and its password both in bytes format.
    """
    p12_data, password = generate_pkcs12_data
    result = serializer.load_pkcs12_bytes(p12_data, password)

    assert result is not None
    assert isinstance(result, PKCS12KeyAndCertificates)


def test_load_pkcs12_invalid_p12type() -> None:
    """This checks if function loads pkcs12 data, when input is invalid.

    particularly when pkcs12 data is wrong but password is in bytes format.
    """
    with pytest.raises(TypeError):
        serializer.load_pkcs12_bytes(' ', b'testing321')  # type: ignore[arg-type]


def test_load_pkcs12_invalid_password(generate_pkcs12_data: tuple[bytes, bytes]) -> None:
    """This checks if function loads pkcs12 data, when input is invalid.

    particularly when pkcs12 data is in bytes format but password is not.

    Args:
        generate_pkcs12_data: contains pkcs12 data and its password both in bytes format.
    """
    p12_data, _ = generate_pkcs12_data
    with pytest.raises(TypeError):
        serializer.load_pkcs12_bytes(p12_data, '1234')  # type: ignore[arg-type]


def test_load_pkcs12_invalid_password_or_pkcs12() -> None:
    """This checks if function loads pkcs12 data, when input is invalid.

    particularly when pkcs12 data and password are in bytes format but empty.
    """
    with pytest.raises(ValueError, match='Failed to load PKCS#12 bytes. Either wrong password or malformed data.'):
        serializer.load_pkcs12_bytes(b'', b'')


def test_load_pkcs12_corrupt_data() -> None:
    """This checks if function loads pkcs12 data, when input is invalid.

    particularly when pkcs12 data and password are in bytes format but corrupt.
    """
    with pytest.raises(ValueError, match='Failed to load PKCS#12 bytes'):
        serializer.load_pkcs12_bytes(b'\x00\x01\x02', b'testing321')


def test_get_encryption_algorithme_valid() -> None:
    """This checks if function gets encryption algorithm."""
    result = serializer.get_encryption_algorithm(b'testing321')
    assert isinstance(result, BestAvailableEncryption)


def test_get_encryption_algorithm_invalid() -> None:
    """This checks if function gets encryption algorithm. when input is invalid."""
    with pytest.raises(TypeError):
        serializer.get_encryption_algorithm(' ')  # type: ignore[arg-type]


def test_get_encryption_algorithm_zero() -> None:
    """This checks if function gets encryption algorithm when input is None."""
    result = serializer.get_encryption_algorithm(None)
    assert isinstance(result, NoEncryption)


def test_get_encryption_algorithm_empty_password() -> None:
    """This checks if function gets encryption algorithm when input is empty."""
    result = serializer.get_encryption_algorithm(b'')
    assert isinstance(result, NoEncryption)


# From here test for PublicKeySerializer Starts


def test_init_publickey_valid_key(generate_public_key: RSAPublicKey) -> None:
    """This checks if function initializes public key serializer with given public key.

    Args:
        generate_public_key: RSAPublicKey.
    """
    public_key = generate_public_key
    serializer = PublicKeySerializer(public_key)
    assert serializer.as_crypto() == public_key


def test_init_publickey_invalid_key() -> None:
    """This checks if function fails to initialize public key serializer when given invalid key."""
    with pytest.raises(TypeError, match='Expected a public key object'):
        PublicKeySerializer('invalid_key')  # type: ignore[arg-type]


def test_publickey_from_der(generate_public_key: RSAPublicKey) -> None:
    """This checks if function loads public key serializer with given publickey in DER format.

    Args:
        generate_public_key: contains public key.
    """
    public_key = generate_public_key
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    serializer = PublicKeySerializer.from_der(der_bytes)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)


def test_publickey_from_der_invalid() -> None:
    """This checks if function fails to initializer public key serializer if given invalid DER format."""
    with pytest.raises(ValueError, match='Failed to load the public key in DER format'):
        PublicKeySerializer.from_der(b'\x00\x01\x02')


def test_publickey_from_pem(generate_public_key: RSAPublicKey) -> None:
    """This checks if function loads public key serializer with given publickey in PEM format.

    Args:
        generate_public_key: contains public key.
    """
    public_key = generate_public_key
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    serializer = PublicKeySerializer.from_pem(pem_bytes)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)


def test_publickey_from_pem_invalid() -> None:
    """This checks if function fails to initializer public key serializer if given invalid PEM format."""
    with pytest.raises(ValueError, match='Failed to load the public key in PEM format'):
        PublicKeySerializer.from_pem(b'INVALID PEM DATA')


def test_publickey_from_private_key(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function loads public key serializer when given private key object.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    serializer = PublicKeySerializer.from_private_key(private_key)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)


def test_publickey_from_private_key_invalid() -> None:
    """This checks if function fails when given invalid private key object to load public key serializer."""
    with pytest.raises(TypeError, match='Expected a private key object'):
        PublicKeySerializer.from_private_key('invalid_private_key')  # type: ignore[arg-type]


def test_from_private_key_with_public_key(generate_public_key: RSAPublicKey) -> None:
    """This checks if function fails to load when given public key object instead of private key object.

    Args:
        generate_public_key: contains public key.
    """
    public_key = generate_public_key
    with pytest.raises(TypeError, match='Expected a private key object'):
        PublicKeySerializer.from_private_key(public_key)  # type: ignore[arg-type]


def test_publickey_from_certificate(generate_certificate: Certificate) -> None:
    """This checks if function loads public key serializer with given a certificate object.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate

    serializer = PublicKeySerializer.from_certificate(certificate)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)


def test_publickey_from_certificate_invalid() -> None:
    """This checks if function fails to load a public key if given invalid certificate object."""
    with pytest.raises(TypeError, match='Expected a certificate object'):
        PublicKeySerializer.from_certificate('invalid_certificate')  # type: ignore[arg-type]


def test_publickey_as_der(generate_public_key: RSAPublicKey) -> None:
    """This checks if function can get saved public key in DER format.

    Args:
        generate_public_key: contains public key.
    """
    public_key = generate_public_key
    serializer = PublicKeySerializer(public_key)

    der_bytes = serializer.as_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_publickey_as_pem(generate_public_key: RSAPublicKey) -> None:
    """This checks if function can get saved public key in PEM format.

    Args:
        generate_public_key: contains public key.
    """
    public_key = generate_public_key
    serializer = PublicKeySerializer(public_key)

    pem_bytes = serializer.as_pem()
    assert isinstance(pem_bytes, bytes)
    assert b'-----BEGIN PUBLIC KEY-----' in pem_bytes


# Here Starts Test Cases for PrivateKeySerializer


def test_private_key_serializer_init(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function loads private key serializer from given private key object.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    serializer = PrivateKeySerializer(private_key)
    assert serializer.as_crypto() == private_key


def test_private_key_serializer_invalid_init() -> None:
    """This checks if function fails to load private key serializer when given an invalid private key object."""
    with pytest.raises(TypeError, match='Expected a private key object'):
        PrivateKeySerializer('invalid_private_key')  # type: ignore[arg-type]


def test_private_key_from_pem(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function loads private key serializer from private key in pem format.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    serializer = PrivateKeySerializer.from_pem(pem_bytes)
    assert isinstance(serializer.as_crypto(), RSAPrivateKey)


def test_private_key_from_pem_invalid() -> None:
    """This checks if function fails when given private key in invalid pem format."""
    with pytest.raises(ValueError, match='Failed to load the private key in PEM format'):
        PrivateKeySerializer.from_pem(b'INVALID PEM DATA')


def test_private_key_from_pem_invalid_type() -> None:
    """This checks if function fails to load private key serializer when given private key in invalid pem type."""
    with pytest.raises(TypeError, match='Expected private_key to be a bytes object'):
        PrivateKeySerializer.from_pem(12345)  # type: ignore[arg-type]


def test_private_key_from_der(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function can load private key serializer when given private key in der format.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    der_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    serializer = PrivateKeySerializer.from_der(der_bytes)
    assert isinstance(serializer.as_crypto(), RSAPrivateKey)


def test_private_key_from_der_invalid() -> None:
    """This checks if function fails to load private key serializer when given private key in invalid der format."""
    with pytest.raises(ValueError, match='Failed to load the private key in DER format'):
        PrivateKeySerializer.from_der(b'\x00\x01\x02')


def test_private_key_from_der_wrong_type() -> None:
    """This checks if function fails to load private key serializer when given private key in wrong dem type."""
    with pytest.raises(TypeError, match='Expected private_key to be a bytes object'):
        PrivateKeySerializer.from_der(12345)  # type: ignore[arg-type]


def test_private_key_from_pkcs12_bytes(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function loads private key serializer from pkcs12 bytes object.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    pkcs12_bytes = pkcs12.serialize_key_and_certificates(
        name=b'test',
        key=private_key,
        cert=None,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )

    serializer = PrivateKeySerializer.from_pkcs12_bytes(pkcs12_bytes)
    assert isinstance(serializer.as_crypto(), RSAPrivateKey)


def test_private_key_from_pkcs12_invalid() -> None:
    """This checks if function fails when given invalid pkcs12 bytes object."""
    with pytest.raises(ValueError, match='Failed to load PKCS#12 bytes'):
        PrivateKeySerializer.from_pkcs12_bytes(b' ')


def test_private_key_as_pkcs1_der(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function can get private key as bytes in PKCS#1 DER format.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    serializer = PrivateKeySerializer(private_key)

    der_bytes = serializer.as_pkcs1_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_private_key_as_pkcs1_pem(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function can get private key as bytes in PKCS#1 PEM format.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    serializer = PrivateKeySerializer(private_key)

    pem_bytes = serializer.as_pkcs1_pem()
    assert isinstance(pem_bytes, bytes)
    assert b'-----BEGIN RSA PRIVATE KEY-----' in pem_bytes


def test_private_key_as_pkcs8_der(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function can get private key as bytes in PKCS#8 DER format.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    serializer = PrivateKeySerializer(private_key)

    der_bytes = serializer.as_pkcs8_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_private_key_as_pkcs8_pem(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function can get private key as bytes in PKCS#8 PEM format.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    serializer = PrivateKeySerializer(private_key)

    pem_bytes = serializer.as_pkcs8_pem()
    assert isinstance(pem_bytes, bytes)
    assert b'-----BEGIN PRIVATE KEY-----' in pem_bytes


def test_private_key_as_pkcs12(generate_private_key: RSAPrivateKey) -> None:
    """This checks if function can get private key as bytes in PKCS#12 structure.

    Args:
        generate_private_key: contains private key.
    """
    private_key = generate_private_key
    serializer = PrivateKeySerializer(private_key)

    pkcs12_bytes = serializer.as_pkcs12()
    assert isinstance(pkcs12_bytes, bytes)
    assert len(pkcs12_bytes) > 0


def test_private_key_public_key_serializer(
    generate_private_key: RSAPrivateKey, generate_public_key: RSAPublicKey
) -> None:
    """This checks if function can load the public key serializer from private key serializer.

    Args:
        generate_private_key: contains private key.
        generate_public_key: contains public key.
    """
    private_key, public_key = generate_private_key, generate_public_key
    serializer = PrivateKeySerializer(private_key)

    public_serializer = serializer.public_key_serializer
    assert isinstance(public_serializer, PublicKeySerializer)
    assert public_serializer.as_crypto() == public_key


### from here pytest for certificate serializer ###


def test_certificate_serializer_init(generate_certificate: Certificate) -> None:
    """This checks if function can initializer the certificate key serializer.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    serializer = CertificateSerializer(certificate)
    assert serializer.as_crypto() == certificate


def test_certificate_serializer_invalid_init() -> None:
    """This checks if function fails  to initializer certificate serializer when given invalid certificate."""
    with pytest.raises(TypeError, match='Expected a certificate object'):
        CertificateSerializer('invalid_certificate')  # type: ignore[arg-type]


def test_certificate_serializer_from_pem(generate_certificate: Certificate) -> None:
    """This checks if function can load the certificate serializer from certificate in PEM format.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    pem_bytes = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    serializer = CertificateSerializer.from_pem(pem_bytes)
    assert serializer.as_crypto() == certificate


def test_certificate_serializer_from_pem_invalid() -> None:
    """This checks if function fails when given invalid certificate in PEM format."""
    with pytest.raises(ValueError, match='Failed to load the provided certificate in PEM format'):
        CertificateSerializer.from_pem(b'INVALID PEM DATA')


def test_certificate_serializer_from_pem_wrong_type() -> None:
    """This checks if function fails to load certificate from PEM.

    when given invalid certificate in wrong format.
    """
    with pytest.raises(TypeError, match='Expected the certificate to be a bytes object'):
        CertificateSerializer.from_pem(12345)  # type: ignore[arg-type]


def test_certificate_serializer_from_der(generate_certificate: Certificate) -> None:
    """This checks if function can load the certificate serializer from certificate in DER format.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    der_bytes = certificate.public_bytes(encoding=serialization.Encoding.DER)

    serializer = CertificateSerializer.from_der(der_bytes)
    assert serializer.as_crypto() == certificate


def test_certificate_serializer_from_der_invalid() -> None:
    """This checks if function fails to load certificate from DER when given invalid certificate in DER format."""
    with pytest.raises(ValueError, match='Failed to load the provided certificate in DER format'):
        CertificateSerializer.from_der(b'\x00\x01\x02')


def test_certificate_serializer_from_der_wrong_type() -> None:
    """This checks if function fails to load certificate from DER when given invalid certificate in wrong format."""
    with pytest.raises(TypeError, match='Expected the certificate to be a bytes object'):
        CertificateSerializer.from_der(12345)  # type: ignore[arg-type]


def test_certificate_serializer_as_pem(generate_certificate: Certificate) -> None:
    """This checks if function can get the certificate in PEM format.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    serializer = CertificateSerializer(certificate)

    pem_bytes = serializer.as_pem()
    assert isinstance(pem_bytes, bytes)
    assert b'-----BEGIN CERTIFICATE-----' in pem_bytes


def test_certificate_serializer_as_der(generate_certificate: Certificate) -> None:
    """This checks if function can get the certificate in DER format.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    serializer = CertificateSerializer(certificate)

    der_bytes = serializer.as_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_certificate_serializer_as_pkcs7_pem(generate_certificate: Certificate) -> None:
    """This checks if function can get the certificate in pkcs7 format.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    serializer = CertificateSerializer(certificate)

    pkcs7_pem_bytes = serializer.as_pkcs7_pem()
    assert isinstance(pkcs7_pem_bytes, bytes)
    assert len(pkcs7_pem_bytes) > 0


def test_certificate_serializer_as_pkcs7_der(generate_certificate: Certificate) -> None:
    """This checks if function can get the certificate in pkcs7 DER format.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    serializer = CertificateSerializer(certificate)

    pkcs7_der_bytes = serializer.as_pkcs7_der()
    assert isinstance(pkcs7_der_bytes, bytes)
    assert len(pkcs7_der_bytes) > 0


def test_certificate_serializer_public_key(generate_certificate: Certificate) -> None:
    """This checks if function can get the public key from certificate serializer.

    Args:
        generate_certificate: contains certificate.
    """
    certificate = generate_certificate
    serializer = CertificateSerializer(certificate)
    public_key = serializer.public_key
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_certificate_serializer_key_serializer(generate_certificate: Certificate) -> None:
    """This checks if function can load the public key serializer from certificate serializer."""
    certificate = generate_certificate
    serializer = CertificateSerializer(certificate)

    public_key_serializer = serializer.public_key_serializer
    assert isinstance(public_key_serializer, PublicKeySerializer)
    assert isinstance(public_key_serializer.as_crypto(), rsa.RSAPublicKey)


### From here test starts for CertificateCollectionSerializer

EXPECTED_COLLECTION_SIZE = 3


def test_certificate_collection_serializer_init(generate_certificates: list[Certificate]) -> None:
    """It checks if function initialize a CertificateCollectionSerializer with the provided list of certificate objects.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer = CertificateCollectionSerializer(generate_certificates)
    assert len(serializer.as_crypto()) == EXPECTED_COLLECTION_SIZE


def test_certificate_collection_serializer_init_empty() -> None:
    """This checks if initialization of collection serializer fails when list is empty."""
    serializer = CertificateCollectionSerializer([])
    assert len(serializer.as_crypto()) == 0


def test_certificate_collection_serializer_invalid_init() -> None:
    """This checks if initialization of collection serializer fails when provided invalid type."""
    with pytest.raises(TypeError):
        CertificateCollectionSerializer('invalid_certificate_list')  # type: ignore[arg-type]


def test_certificate_collection_serializer_invalid_cert_object() -> None:
    """This checks if initialization of collection serializer fails when provided invalid object type."""
    with pytest.raises(TypeError):
        CertificateCollectionSerializer(['invalid_certificate'])  # type: ignore[list-item]


def test_certificate_collection_serializer_from_list_of_pem(generate_certificates: list[Certificate]) -> None:
    """This checks if function can load the certificates collection serializer from list of certificates in PEM format.

    Args:
        generate_certificates: contains list of certificates.
    """
    pem_bytes_list = [cert.public_bytes(encoding=serialization.Encoding.PEM) for cert in generate_certificates]
    serializer = CertificateCollectionSerializer.from_list_of_pem(pem_bytes_list)
    assert len(serializer.as_crypto()) == EXPECTED_COLLECTION_SIZE


def test_certificate_collection_serializer_from_list_of_der(generate_certificates: list[Certificate]) -> None:
    """This checks if function can load the certificates collection serializer from list of certificates in DER format.

    Args:
        generate_certificates: contains list of certificates.
    """
    der_bytes_list = [cert.public_bytes(encoding=serialization.Encoding.DER) for cert in generate_certificates]
    serializer = CertificateCollectionSerializer.from_list_of_der(der_bytes_list)
    assert len(serializer.as_crypto()) == EXPECTED_COLLECTION_SIZE


def test_certificate_collection_serializer_from_pem(generate_certificates: list[Certificate]) -> None:
    """This checks if function can load the certificates from PEM format.

    Args:
        generate_certificates: contains list of certificates.
    """
    pem_bytes = b''.join(cert.public_bytes(encoding=serialization.Encoding.PEM) for cert in generate_certificates)
    serializer = CertificateCollectionSerializer.from_pem(pem_bytes)
    assert len(serializer.as_crypto()) == EXPECTED_COLLECTION_SIZE


def test_certificate_collection_serializer_from_pem_invalid() -> None:
    """This checks if function fails when load the certificate collection serializer from invalid PEM format."""
    with pytest.raises(
        ValueError,
        match='Failed to load the provided certificates in PEM format. Either wrong format or data is corrupted.',
    ):
        CertificateCollectionSerializer.from_pem(b'INVALID PEM DATA')


def test_certificate_collection_serializer_from_der_invalid() -> None:
    """This checks if function fails when load the certificate collection serializer from invalid DER format."""
    with pytest.raises(
        ValueError,
        match='Failed to load the provided certificate in DER format. Either wrong format or data is corrupted.',
    ):
        CertificateCollectionSerializer.from_list_of_der([b'\x00\x01\x02'])


def test_certificate_collection_serializer_as_pem(generate_certificates: list[Certificate]) -> None:
    """Checks if function gets certificate in PEM format from given CertificateCollectionSerializer.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer = CertificateCollectionSerializer(generate_certificates)
    pem_bytes = serializer.as_pem()
    assert isinstance(pem_bytes, bytes)
    assert b'-----BEGIN CERTIFICATE-----' in pem_bytes


def test_certificate_collection_serializer_as_der_list(generate_certificates: list[Certificate]) -> None:
    """Checks if function gets certificate in DER format from given CertificateCollectionSerializer.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer = CertificateCollectionSerializer(generate_certificates)
    der_list = serializer.as_der_list()
    assert isinstance(der_list, list)
    assert len(der_list) == EXPECTED_COLLECTION_SIZE


def test_certificate_collection_serializer_as_pkcs7_pem(generate_certificates: list[Certificate]) -> None:
    """Checks if function gets certificate in pkcs7 PEM format from given CertificateCollectionSerializer.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer = CertificateCollectionSerializer(generate_certificates)
    pkcs7_pem = serializer.as_pkcs7_pem()
    assert isinstance(pkcs7_pem, bytes)
    assert len(pkcs7_pem) > 0


def test_certificate_collection_serializer_as_pkcs7_der(generate_certificates: list[Certificate]) -> None:
    """Checks if function gets certificate in pkcs7 PEM format from given CertificateCollectionSerializer.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer = CertificateCollectionSerializer(generate_certificates)
    pkcs7_der = serializer.as_pkcs7_der()
    assert isinstance(pkcs7_der, bytes)
    assert len(pkcs7_der) > 0


def test_add_certificate_to_certificate_collection_serializer(generate_certificates: list[Certificate]) -> None:
    """Checks if function adds certificate to certificate collection serializer.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer = CertificateCollectionSerializer(generate_certificates[:2])
    new_cert = generate_certificates[2]
    new_collection = serializer + new_cert

    assert len(new_collection.as_crypto()) == EXPECTED_COLLECTION_SIZE


def test_add_certificate_collection_to_certificate_collection_serializer(
    generate_certificates: list[Certificate],
) -> None:
    """Checks if function adds certificate collection serializer to another certificate collection serializer.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer1 = CertificateCollectionSerializer(generate_certificates[:2])
    serializer2 = CertificateCollectionSerializer([generate_certificates[2]])

    new_collection = serializer1 + serializer2
    assert len(new_collection.as_crypto()) == EXPECTED_COLLECTION_SIZE


def test_len_function_of_certificate_collection_serializer(generate_certificates: list[Certificate]) -> None:
    """Checks if function returns the length of certificate collection serializer.

    Args:
        generate_certificates: contains list of certificates.
    """
    serializer = CertificateCollectionSerializer(generate_certificates)
    assert len(serializer) == EXPECTED_COLLECTION_SIZE
