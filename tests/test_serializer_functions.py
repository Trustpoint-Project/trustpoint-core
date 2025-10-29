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

# ruff: noqa: SLF001, PLR2004


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
def generate_certificate(generate_private_key: RSAPrivateKey) -> Certificate:
    """Fixture to generate a self-signed certificate for testing.

    Returns:
        Certificate
    """
    private_key = generate_private_key
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

@pytest.fixture
def generate_private_key_reference() -> serializer.PrivateKeyReference:
    """Fixture to generate PrivateKeyReference for testing.

    Returns:
        PrivateKeyReference object.
    """
    return serializer.PrivateKeyReference.hsm_provided(
        key_label='test_key_id',
        key_type=rsa.RSAPrivateKey,
        key_size=2048
    )


@pytest.fixture
def generate_credential_data() -> tuple[RSAPrivateKey, Certificate, list[Certificate]]:
    """Fixture to generate credential data for testing.

    Returns:
        Tuple containing private key, certificate, and additional certificates.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Generate main certificate
    subject = issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test Certificate')])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(private_key, algorithm=hashes.SHA256())
    )

    # Generate additional certificates
    additional_certs = []
    for i in range(2):
        additional_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        additional_subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, f'Additional Cert {i}')])
        additional_cert = (
            x509.CertificateBuilder()
            .subject_name(additional_subject)
            .issuer_name(additional_subject)
            .public_key(additional_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
            .sign(additional_key, algorithm=hashes.SHA256())
        )
        additional_certs.append(additional_cert)

    return private_key, certificate, additional_certs


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
    with pytest.raises(ValueError, match='Failed to get the BestAvailableEncryption algorithm.'):
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
    with pytest.raises(TypeError, match='Object of type .* does not have a public_key\\(\\) method'):
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

### From here test starts for CredentialSerializer

def test_credential_serializer_init_all_params(
        generate_credential_data: tuple[RSAPrivateKey, Certificate, list[Certificate]]) -> None:
    """This checks if CredentialSerializer initializes with all parameters.

    Args:
        generate_credential_data: Contains private key, certificate, and additional certificates.
    """
    private_key, certificate, additional_certs = generate_credential_data

    credential = serializer.CredentialSerializer(
        private_key=private_key,
        certificate=certificate,
        additional_certificates=additional_certs
    )

    assert credential.private_key == private_key
    assert credential.certificate == certificate
    assert credential.additional_certificates == additional_certs


def test_credential_serializer_init_minimal() -> None:
    """This checks if CredentialSerializer initializes with minimal parameters."""
    credential = serializer.CredentialSerializer()

    assert credential.private_key is None
    assert credential.certificate is None
    assert credential.additional_certificates == []


def test_credential_serializer_private_key_property(generate_private_key: RSAPrivateKey) -> None:
    """This checks if private_key property works correctly."""
    credential = serializer.CredentialSerializer(private_key=generate_private_key)
    assert credential.private_key == generate_private_key

def test_credential_serializer_private_key_setter(generate_private_key: RSAPrivateKey) -> None:
    """This checks if private_key setter works correctly."""
    credential = serializer.CredentialSerializer()
    credential.private_key = generate_private_key
    assert credential.private_key == generate_private_key


def test_credential_serializer_private_key_deleter() -> None:
    """This checks if private_key deleter works correctly."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    credential = serializer.CredentialSerializer(private_key=private_key)

    del credential.private_key
    assert credential.private_key is None


def test_credential_serializer_get_private_key_serializer(generate_private_key: RSAPrivateKey) -> None:
    """This checks if get_private_key_serializer works correctly."""
    credential = serializer.CredentialSerializer(private_key=generate_private_key)
    private_key_serializer = credential.get_private_key_serializer()

    assert isinstance(private_key_serializer, PrivateKeySerializer)
    assert private_key_serializer.as_crypto() == generate_private_key

def test_credential_serializer_get_private_key_serializer_none() -> None:
    """This checks if get_private_key_serializer returns None when no private key."""
    credential = serializer.CredentialSerializer()
    assert credential.get_private_key_serializer() is None

def test_credential_serializer_private_key_location_property() -> None:
    """This checks if private_key_location property works correctly."""
    credential = serializer.CredentialSerializer()
    assert credential._private_key_reference.location == serializer.PrivateKeyLocation.SOFTWARE

def test_credential_serializer_private_key_location_setter() -> None:
    """This checks if private_key_location setter works correctly."""
    credential = serializer.CredentialSerializer()
    credential._private_key_reference = serializer.PrivateKeyReference(
        location=serializer.PrivateKeyLocation.HSM_PROVIDED,
        key_label='test_key'
    )
    assert credential._private_key_reference.location == serializer.PrivateKeyLocation.HSM_PROVIDED


def test_credential_serializer_is_hsm_key() -> None:
    """This checks if is_hsm_key works correctly."""
    # Test with software key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    credential = serializer.CredentialSerializer(private_key=private_key)
    assert not credential.is_hsm_key

    # Test with HSM key
    credential_hsm = serializer.CredentialSerializer(
        private_key_reference=serializer.PrivateKeyReference.hsm_provided(key_label='test_key')
    )
    assert credential_hsm.is_hsm_key


def test_credential_serializer_is_hsm_generated_key() -> None:
    """This checks if is_hsm_generated_key works correctly."""
    credential = serializer.CredentialSerializer(
        private_key_reference=serializer.PrivateKeyReference.hsm_generated(key_label='test_key')
    )
    assert credential.is_hsm_generated_key

    credential_software = serializer.CredentialSerializer()
    assert not credential_software.is_hsm_generated_key


def test_credential_serializer_get_hsm_key_reference(
        generate_private_key_reference: serializer.PrivateKeyReference) -> None:
    """This checks if get_hsm_key_reference works correctly."""
    credential = serializer.CredentialSerializer(
        private_key_reference=generate_private_key_reference
    )

    result = credential.get_hsm_key_reference()
    assert result == generate_private_key_reference
    assert result is not None
    assert result.key_label == 'test_key_id'

def test_credential_serializer_certificate_property(generate_certificate: Certificate) -> None:
    """This checks if certificate property works correctly."""
    credential = serializer.CredentialSerializer(certificate=generate_certificate)
    assert credential.certificate == generate_certificate

def test_credential_serializer_certificate_setter(generate_certificate: Certificate) -> None:
    """This checks if certificate setter works correctly."""
    credential = serializer.CredentialSerializer()
    credential.certificate = generate_certificate
    assert credential.certificate == generate_certificate


def test_credential_serializer_certificate_deleter() -> None:
    """This checks if certificate deleter works correctly."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'Test Certificate')])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(private_key, algorithm=hashes.SHA256())
    )

    credential = serializer.CredentialSerializer(certificate=certificate)
    del credential.certificate
    assert credential.certificate is None


def test_credential_serializer_get_certificate_serializer(generate_certificate: Certificate) -> None:
    """This checks if get_certificate_serializer works correctly."""
    credential = serializer.CredentialSerializer(certificate=generate_certificate)
    certificate_serializer = credential.get_certificate_serializer()

    assert isinstance(certificate_serializer, CertificateSerializer)
    assert certificate_serializer.as_crypto() == generate_certificate

def test_credential_serializer_get_certificate_serializer_none() -> None:
    """This checks if get_certificate_serializer returns None when no certificate."""
    credential = serializer.CredentialSerializer()
    assert credential.get_certificate_serializer() is None


def test_credential_serializer_additional_certificates_property(generate_certificates: list[Certificate]) -> None:
    """This checks if additional_certificates property works correctly.

    Args:
        generate_certificates: Contains list of certificates.
    """
    additional_certs = generate_certificates[:2]
    credential = serializer.CredentialSerializer(additional_certificates=additional_certs)
    assert credential.additional_certificates == additional_certs


def test_credential_serializer_additional_certificates_setter(generate_certificates: list[Certificate]) -> None:
    """This checks if additional_certificates setter works correctly.

    Args:
        generate_certificates: Contains list of certificates.
    """
    additional_certs = generate_certificates[:2]
    credential = serializer.CredentialSerializer()
    credential.additional_certificates = additional_certs
    assert credential.additional_certificates == additional_certs


def test_credential_serializer_additional_certificates_deleter(generate_certificates: list[Certificate]) -> None:
    """This checks if additional_certificates deleter works correctly.

    Args:
        generate_certificates: Contains list of certificates.
    """
    additional_certs = generate_certificates[:2]
    credential = serializer.CredentialSerializer(additional_certificates=additional_certs)

    del credential.additional_certificates
    assert credential.additional_certificates == []


def test_credential_serializer_get_additional_certificates_serializer(generate_certificates: list[Certificate]) -> None:
    """This checks if get_additional_certificates_serializer works correctly.

    Args:
        generate_certificates: Contains list of certificates.
    """
    additional_certs = generate_certificates[:2]
    credential = serializer.CredentialSerializer(additional_certificates=additional_certs)
    collection_serializer = credential.get_additional_certificates_serializer()

    assert isinstance(collection_serializer, CertificateCollectionSerializer)
    assert len(collection_serializer.as_crypto()) == 2

def test_credential_serializer_get_additional_certificates_serializer_empty() -> None:
    """This checks if get_additional_certificates_serializer works with empty list."""
    credential = serializer.CredentialSerializer()
    collection_serializer = credential.get_additional_certificates_serializer()

    assert isinstance(collection_serializer, CertificateCollectionSerializer)
    assert len(collection_serializer.as_crypto()) == 0


def test_credential_serializer_from_serializers(generate_certificates: list[Certificate],
                                                generate_private_key: RSAPrivateKey) -> None:
    """This checks if from_serializers class method works correctly.

    Args:
        generate_certificates: Contains list of certificates.
        generate_private_key: Contains private key.
    """
    private_key = generate_private_key
    certificate = generate_certificates[0]
    additional_certs = generate_certificates[1:3]

    private_key_serializer = PrivateKeySerializer(private_key)
    certificate_serializer = CertificateSerializer(certificate)
    collection_serializer = CertificateCollectionSerializer(additional_certs)

    credential = serializer.CredentialSerializer.from_serializers(
        private_key_serializer=private_key_serializer,
        certificate_serializer=certificate_serializer,
        certificate_collection_serializer=collection_serializer
    )

    assert credential.private_key == private_key
    assert credential.certificate == certificate
    assert len(credential.additional_certificates) == 2


def test_credential_serializer_from_serializers_minimal() -> None:
    """This checks if from_serializers works with minimal parameters."""
    credential = serializer.CredentialSerializer.from_serializers()

    assert credential.private_key is None
    assert credential.certificate is None
    assert credential.additional_certificates == []


def test_credential_serializer_from_serializers_invalid() -> None:
    """This checks if from_serializers raises TypeError with invalid input."""
    with pytest.raises(TypeError,
        match='Failed to extract the private key, certificate and certificate collection serializers.'
        ):
        serializer.CredentialSerializer.from_serializers(
            private_key_serializer='invalid'  # type: ignore[arg-type]
        )


def test_credential_serializer_from_pkcs12_bytes(generate_pkcs12_data: tuple[bytes, bytes]) -> None:
    """This checks if from_pkcs12_bytes works correctly."""
    p12_data, password = generate_pkcs12_data
    credential = serializer.CredentialSerializer.from_pkcs12_bytes(p12_data, password)

    assert credential.private_key is not None
    assert credential.certificate is not None


def test_credential_serializer_from_pkcs12_bytes_invalid() -> None:
    """This checks if from_pkcs12_bytes raises ValueError with invalid data."""
    with pytest.raises(ValueError, match='Failed to load PKCS#12 bytes'):
        serializer.CredentialSerializer.from_pkcs12_bytes(b'invalid', b'password')


def test_credential_serializer_from_hsm_key_reference(
        generate_private_key_reference: serializer.PrivateKeyReference) -> None:
    """This checks if initialization with PrivateKeyReference works correctly."""
    credential = serializer.CredentialSerializer(
        private_key_reference=generate_private_key_reference
    )

    assert credential.is_hsm_key
    assert credential.get_hsm_key_reference() == generate_private_key_reference


def test_credential_serializer_from_hsm_key_reference_with_certs(
        generate_certificates: list[Certificate]) -> None:
    """This checks if initialization with PrivateKeyReference and certificates works correctly.

    Args:
        generate_certificates: Contains list of certificates.
    """
    private_key_ref = serializer.PrivateKeyReference.hsm_generated(
        key_label='test',
        key_type=rsa.RSAPrivateKey,
        key_size=2048
    )
    certificate = generate_certificates[0]
    additional_certs = generate_certificates[1:2]

    credential = serializer.CredentialSerializer(
        private_key_reference=private_key_ref,
        certificate=certificate,
        additional_certificates=additional_certs
    )

    assert credential.is_hsm_key
    assert credential.certificate == certificate
    assert len(credential.additional_certificates) == 1


def test_credential_serializer_as_pkcs12(
        generate_credential_data: tuple[RSAPrivateKey, Certificate, list[Certificate]]) -> None:
    """This checks if as_pkcs12 works correctly."""
    private_key, certificate, additional_certs = generate_credential_data
    credential = serializer.CredentialSerializer(
        private_key=private_key,
        certificate=certificate,
        additional_certificates=additional_certs
    )

    pkcs12_bytes = credential.as_pkcs12()
    assert isinstance(pkcs12_bytes, bytes)
    assert len(pkcs12_bytes) > 0


def test_credential_serializer_as_pkcs12_with_password(generate_private_key: RSAPrivateKey,
                                                       generate_certificate: Certificate) -> None:
    """This checks if as_pkcs12 works with password.

    Args:
        generate_private_key: Contains private key.
        generate_certificate: Contains certificate.
    """
    private_key = generate_private_key
    certificate = generate_certificate

    credential = serializer.CredentialSerializer(
        private_key=private_key,
        certificate=certificate
    )

    password = b'testpass123'
    pkcs12_bytes = credential.as_pkcs12(password=password)
    assert isinstance(pkcs12_bytes, bytes)
    assert len(pkcs12_bytes) > 0


def test_credential_serializer_get_full_chain_as_crypto(generate_private_key: RSAPrivateKey,
                                                        generate_certificates: list[Certificate]) -> None:
    """This checks if get_full_chain_as_crypto works correctly.

    Args:
        generate_private_key: Contains private key.
        generate_certificates: Contains list of certificates.
    """
    private_key = generate_private_key
    certificate = generate_certificates[0]
    additional_certs = generate_certificates[1:3]

    credential = serializer.CredentialSerializer(
        private_key=private_key,
        certificate=certificate,
        additional_certificates=additional_certs
    )

    full_chain = credential.get_full_chain_as_crypto()
    assert len(full_chain) == 3
    assert full_chain[0] == certificate


def test_credential_serializer_get_full_chain_as_crypto_no_cert() -> None:
    """This checks if get_full_chain_as_crypto works with no certificate."""
    credential = serializer.CredentialSerializer()
    full_chain = credential.get_full_chain_as_crypto()
    assert len(full_chain) == 0


def test_credential_serializer_get_full_chain_as_serializer(generate_private_key: RSAPrivateKey,
                                                            generate_certificates: list[Certificate]) -> None:
    """This checks if get_full_chain_as_serializer works correctly.

    Args:
        generate_private_key: Contains private key.
        generate_certificates: Contains list of certificates.
    """
    private_key = generate_private_key
    certificate = generate_certificates[0]
    additional_certs = generate_certificates[1:3]

    credential = serializer.CredentialSerializer(
        private_key=private_key,
        certificate=certificate,
        additional_certificates=additional_certs
    )

    full_chain_serializer = credential.get_full_chain_as_serializer()
    assert isinstance(full_chain_serializer, CertificateCollectionSerializer)
    assert len(full_chain_serializer.as_crypto()) == 3

