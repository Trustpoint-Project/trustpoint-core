"""This module contains tests for ML-DSA (Module-Lattice-Based Digital Signature Algorithm) integration."""

from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key

from trustpoint_core.oid import (
    AlgorithmIdentifier,
    KeyPairGenerator,
    PublicKeyAlgorithmOid,
    PublicKeyInfo,
)
from trustpoint_core.serializer import PrivateKeyReference, PrivateKeySerializer

# ruff: noqa: SLF001

MldsaPrivateKey = mldsa.MLDSA44PrivateKey | mldsa.MLDSA65PrivateKey | mldsa.MLDSA87PrivateKey


# Fixtures for ML-DSA key generation
@pytest.fixture
def generate_mldsa44_private_key() -> mldsa.MLDSA44PrivateKey:
    """Fixture to generate ML-DSA-44 private key for testing.

    Returns:
        MLDSA44PrivateKey
    """
    return mldsa.MLDSA44PrivateKey.generate()


@pytest.fixture
def generate_mldsa65_private_key() -> mldsa.MLDSA65PrivateKey:
    """Fixture to generate ML-DSA-65 private key for testing.

    Returns:
        MLDSA65PrivateKey
    """
    return mldsa.MLDSA65PrivateKey.generate()


@pytest.fixture
def generate_mldsa87_private_key() -> mldsa.MLDSA87PrivateKey:
    """Fixture to generate ML-DSA-87 private key for testing.

    Returns:
        MLDSA87PrivateKey
    """
    return mldsa.MLDSA87PrivateKey.generate()


# Tests for PublicKeyAlgorithmOid with ML-DSA keys
def test_public_key_algorithm_oid_from_mldsa44_public_key(
    generate_mldsa44_private_key: mldsa.MLDSA44PrivateKey,
) -> None:
    """Test PublicKeyAlgorithmOid detection from ML-DSA-44 public key.

    Args:
        generate_mldsa44_private_key: ML-DSA-44 private key fixture.
    """
    public_key = generate_mldsa44_private_key.public_key()
    algo_oid = PublicKeyAlgorithmOid.from_public_key(public_key)

    assert algo_oid == PublicKeyAlgorithmOid.ML_DSA_44
    assert algo_oid.verbose_name == 'ML-DSA-44'
    assert algo_oid.dotted_string == '2.16.840.1.101.3.4.3.17'


def test_public_key_algorithm_oid_from_mldsa65_public_key(
    generate_mldsa65_private_key: mldsa.MLDSA65PrivateKey,
) -> None:
    """Test PublicKeyAlgorithmOid detection from ML-DSA-65 public key.

    Args:
        generate_mldsa65_private_key: ML-DSA-65 private key fixture.
    """
    public_key = generate_mldsa65_private_key.public_key()
    algo_oid = PublicKeyAlgorithmOid.from_public_key(public_key)

    assert algo_oid == PublicKeyAlgorithmOid.ML_DSA_65
    assert algo_oid.verbose_name == 'ML-DSA-65'
    assert algo_oid.dotted_string == '2.16.840.1.101.3.4.3.18'


def test_public_key_algorithm_oid_from_mldsa87_public_key(
    generate_mldsa87_private_key: mldsa.MLDSA87PrivateKey,
) -> None:
    """Test PublicKeyAlgorithmOid detection from ML-DSA-87 public key.

    Args:
        generate_mldsa87_private_key: ML-DSA-87 private key fixture.
    """
    public_key = generate_mldsa87_private_key.public_key()
    algo_oid = PublicKeyAlgorithmOid.from_public_key(public_key)

    assert algo_oid == PublicKeyAlgorithmOid.ML_DSA_87
    assert algo_oid.verbose_name == 'ML-DSA-87'
    assert algo_oid.dotted_string == '2.16.840.1.101.3.4.3.19'


# Tests for PublicKeyInfo with ML-DSA keys
def test_public_key_info_from_mldsa44_public_key(
    generate_mldsa44_private_key: mldsa.MLDSA44PrivateKey,
) -> None:
    """Test PublicKeyInfo creation from ML-DSA-44 public key.

    Args:
        generate_mldsa44_private_key: ML-DSA-44 private key fixture.
    """
    public_key = generate_mldsa44_private_key.public_key()
    pub_key_info = PublicKeyInfo.from_public_key(public_key)

    assert pub_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ML_DSA_44
    assert str(pub_key_info) == 'ML-DSA-44'
    assert pub_key_info.named_curve is None


def test_public_key_info_from_mldsa65_public_key(
    generate_mldsa65_private_key: mldsa.MLDSA65PrivateKey,
) -> None:
    """Test PublicKeyInfo creation from ML-DSA-65 public key.

    Args:
        generate_mldsa65_private_key: ML-DSA-65 private key fixture.
    """
    public_key = generate_mldsa65_private_key.public_key()
    pub_key_info = PublicKeyInfo.from_public_key(public_key)

    assert pub_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ML_DSA_65
    assert str(pub_key_info) == 'ML-DSA-65'
    assert pub_key_info.named_curve is None


def test_public_key_info_from_mldsa87_public_key(
    generate_mldsa87_private_key: mldsa.MLDSA87PrivateKey,
) -> None:
    """Test PublicKeyInfo creation from ML-DSA-87 public key.

    Args:
        generate_mldsa87_private_key: ML-DSA-87 private key fixture.
    """
    public_key = generate_mldsa87_private_key.public_key()
    pub_key_info = PublicKeyInfo.from_public_key(public_key)

    assert pub_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ML_DSA_87
    assert str(pub_key_info) == 'ML-DSA-87'
    assert pub_key_info.named_curve is None


def test_public_key_info_from_mldsa44_private_key(
    generate_mldsa44_private_key: mldsa.MLDSA44PrivateKey,
) -> None:
    """Test PublicKeyInfo creation from ML-DSA-44 private key.

    Args:
        generate_mldsa44_private_key: ML-DSA-44 private key fixture.
    """
    pub_key_info = PublicKeyInfo.from_private_key(generate_mldsa44_private_key)

    assert pub_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ML_DSA_44
    assert str(pub_key_info) == 'ML-DSA-44'


@pytest.mark.parametrize(
    ('private_key_type', 'public_key_size'),
    [
        (mldsa.MLDSA44PrivateKey, 1312),
        (mldsa.MLDSA65PrivateKey, 1952),
        (mldsa.MLDSA87PrivateKey, 2592),
    ],
)
def test_public_key_info_mldsa_key_size_is_fixed(
    private_key_type: type[mldsa.MLDSA44PrivateKey | mldsa.MLDSA65PrivateKey | mldsa.MLDSA87PrivateKey],
    public_key_size: int,
) -> None:
    """Test that ML-DSA public-key sizes are fixed and validated."""
    public_key_info = PublicKeyInfo.from_private_key(private_key_type.generate())

    assert public_key_info.key_size == public_key_size
    with pytest.raises(ValueError, match='public key size'):
        PublicKeyInfo(public_key_info.public_key_algorithm_oid, key_size=public_key_size + 1)


# Tests for KeyPairGenerator with ML-DSA keys
def test_key_pair_generator_for_mldsa44_public_key(
    generate_mldsa44_private_key: mldsa.MLDSA44PrivateKey,
) -> None:
    """Test KeyPairGenerator with ML-DSA-44 public key.

    Args:
        generate_mldsa44_private_key: ML-DSA-44 private key fixture.
    """
    public_key = generate_mldsa44_private_key.public_key()
    generated_key = KeyPairGenerator.generate_key_pair_for_public_key(public_key)

    assert isinstance(generated_key, mldsa.MLDSA44PrivateKey)
    assert isinstance(generated_key.public_key(), mldsa.MLDSA44PublicKey)


def test_key_pair_generator_for_mldsa65_public_key(
    generate_mldsa65_private_key: mldsa.MLDSA65PrivateKey,
) -> None:
    """Test KeyPairGenerator with ML-DSA-65 public key.

    Args:
        generate_mldsa65_private_key: ML-DSA-65 private key fixture.
    """
    public_key = generate_mldsa65_private_key.public_key()
    generated_key = KeyPairGenerator.generate_key_pair_for_public_key(public_key)

    assert isinstance(generated_key, mldsa.MLDSA65PrivateKey)
    assert isinstance(generated_key.public_key(), mldsa.MLDSA65PublicKey)


def test_key_pair_generator_for_mldsa87_public_key(
    generate_mldsa87_private_key: mldsa.MLDSA87PrivateKey,
) -> None:
    """Test KeyPairGenerator with ML-DSA-87 public key.

    Args:
        generate_mldsa87_private_key: ML-DSA-87 private key fixture.
    """
    public_key = generate_mldsa87_private_key.public_key()
    generated_key = KeyPairGenerator.generate_key_pair_for_public_key(public_key)

    assert isinstance(generated_key, mldsa.MLDSA87PrivateKey)
    assert isinstance(generated_key.public_key(), mldsa.MLDSA87PublicKey)


def test_key_pair_generator_for_mldsa44_public_key_info() -> None:
    """Test KeyPairGenerator with ML-DSA-44 PublicKeyInfo."""
    pub_key_info = PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ML_DSA_44)
    generated_key = KeyPairGenerator.generate_key_pair_for_public_key_info(pub_key_info)

    assert isinstance(generated_key, mldsa.MLDSA44PrivateKey)


def test_key_pair_generator_for_mldsa65_public_key_info() -> None:
    """Test KeyPairGenerator with ML-DSA-65 PublicKeyInfo."""
    pub_key_info = PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ML_DSA_65)
    generated_key = KeyPairGenerator.generate_key_pair_for_public_key_info(pub_key_info)

    assert isinstance(generated_key, mldsa.MLDSA65PrivateKey)


def test_key_pair_generator_for_mldsa87_public_key_info() -> None:
    """Test KeyPairGenerator with ML-DSA-87 PublicKeyInfo."""
    pub_key_info = PublicKeyInfo(public_key_algorithm_oid=PublicKeyAlgorithmOid.ML_DSA_87)
    generated_key = KeyPairGenerator.generate_key_pair_for_public_key_info(pub_key_info)

    assert isinstance(generated_key, mldsa.MLDSA87PrivateKey)


def test_key_pair_generator_for_mldsa44_private_key(
    generate_mldsa44_private_key: mldsa.MLDSA44PrivateKey,
) -> None:
    """Test KeyPairGenerator with ML-DSA-44 private key.

    Args:
        generate_mldsa44_private_key: ML-DSA-44 private key fixture.
    """
    generated_key = KeyPairGenerator.generate_key_pair_for_private_key(generate_mldsa44_private_key)

    assert isinstance(generated_key, mldsa.MLDSA44PrivateKey)


# Tests for AlgorithmIdentifier with ML-DSA
def test_algorithm_identifier_mldsa44() -> None:
    """Test AlgorithmIdentifier for ML-DSA-44."""
    algo_id = AlgorithmIdentifier.ML_DSA_44

    assert algo_id.verbose_name == 'ML-DSA-44'
    assert algo_id.dotted_string == '2.16.840.1.101.3.4.3.17'
    assert algo_id.public_key_algo_oid == PublicKeyAlgorithmOid.ML_DSA_44
    assert algo_id.hash_algorithm is None
    assert algo_id.padding_scheme is None


def test_algorithm_identifier_mldsa65() -> None:
    """Test AlgorithmIdentifier for ML-DSA-65."""
    algo_id = AlgorithmIdentifier.ML_DSA_65

    assert algo_id.verbose_name == 'ML-DSA-65'
    assert algo_id.dotted_string == '2.16.840.1.101.3.4.3.18'
    assert algo_id.public_key_algo_oid == PublicKeyAlgorithmOid.ML_DSA_65
    assert algo_id.hash_algorithm is None
    assert algo_id.padding_scheme is None


def test_algorithm_identifier_mldsa87() -> None:
    """Test AlgorithmIdentifier for ML-DSA-87."""
    algo_id = AlgorithmIdentifier.ML_DSA_87

    assert algo_id.verbose_name == 'ML-DSA-87'
    assert algo_id.dotted_string == '2.16.840.1.101.3.4.3.19'
    assert algo_id.public_key_algo_oid == PublicKeyAlgorithmOid.ML_DSA_87
    assert algo_id.hash_algorithm is None
    assert algo_id.padding_scheme is None


def test_algorithm_identifier_from_dotted_string_mldsa44() -> None:
    """Test AlgorithmIdentifier.from_dotted_string for ML-DSA-44."""
    algo_id = AlgorithmIdentifier.from_dotted_string('2.16.840.1.101.3.4.3.17')

    assert algo_id == AlgorithmIdentifier.ML_DSA_44
    assert algo_id.verbose_name == 'ML-DSA-44'


def test_algorithm_identifier_from_verbose_name_mldsa65() -> None:
    """Test AlgorithmIdentifier.from_verbose_name for ML-DSA-65."""
    algo_id = AlgorithmIdentifier.from_verbose_name('ML-DSA-65')

    assert algo_id == AlgorithmIdentifier.ML_DSA_65
    assert algo_id.dotted_string == '2.16.840.1.101.3.4.3.18'


# Tests for PrivateKeyReference with ML-DSA keys
def test_private_key_reference_from_mldsa44_private_key(
    generate_mldsa44_private_key: mldsa.MLDSA44PrivateKey,
) -> None:
    """Test PrivateKeyReference creation from ML-DSA-44 private key.

    Args:
        generate_mldsa44_private_key: ML-DSA-44 private key fixture.
    """
    key_ref = PrivateKeyReference.from_private_key(generate_mldsa44_private_key)

    assert key_ref.key_type is type(generate_mldsa44_private_key)
    assert key_ref.is_software()
    assert not key_ref.is_hsm_key()


def test_private_key_reference_from_mldsa65_private_key(
    generate_mldsa65_private_key: mldsa.MLDSA65PrivateKey,
) -> None:
    """Test PrivateKeyReference creation from ML-DSA-65 private key.

    Args:
        generate_mldsa65_private_key: ML-DSA-65 private key fixture.
    """
    key_ref = PrivateKeyReference.from_private_key(generate_mldsa65_private_key)

    assert key_ref.key_type is type(generate_mldsa65_private_key)
    assert key_ref.is_software()


def test_private_key_reference_from_mldsa87_private_key(
    generate_mldsa87_private_key: mldsa.MLDSA87PrivateKey,
) -> None:
    """Test PrivateKeyReference creation from ML-DSA-87 private key.

    Args:
        generate_mldsa87_private_key: ML-DSA-87 private key fixture.
    """
    key_ref = PrivateKeyReference.from_private_key(generate_mldsa87_private_key)

    assert key_ref.key_type is type(generate_mldsa87_private_key)
    assert key_ref.is_software()


# Tests for PrivateKeySerializer with ML-DSA keys
def test_private_key_serializer_init_mldsa44(
    generate_mldsa44_private_key: mldsa.MLDSA44PrivateKey,
) -> None:
    """Test PrivateKeySerializer initialization with ML-DSA-44 key.

    Args:
        generate_mldsa44_private_key: ML-DSA-44 private key fixture.
    """
    serializer = PrivateKeySerializer(generate_mldsa44_private_key)
    assert serializer.as_crypto() == generate_mldsa44_private_key


def test_private_key_serializer_init_mldsa65(
    generate_mldsa65_private_key: mldsa.MLDSA65PrivateKey,
) -> None:
    """Test PrivateKeySerializer initialization with ML-DSA-65 key.

    Args:
        generate_mldsa65_private_key: ML-DSA-65 private key fixture.
    """
    serializer = PrivateKeySerializer(generate_mldsa65_private_key)
    assert serializer.as_crypto() == generate_mldsa65_private_key


def test_private_key_serializer_init_mldsa87(
    generate_mldsa87_private_key: mldsa.MLDSA87PrivateKey,
) -> None:
    """Test PrivateKeySerializer initialization with ML-DSA-87 key.

    Args:
        generate_mldsa87_private_key: ML-DSA-87 private key fixture.
    """
    serializer = PrivateKeySerializer(generate_mldsa87_private_key)
    assert serializer.as_crypto() == generate_mldsa87_private_key


@pytest.mark.parametrize(
    'private_key_type',
    [mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey],
)
def test_mldsa_pkcs8_round_trip_and_signature_verification(
    private_key_type: type[mldsa.MLDSA44PrivateKey | mldsa.MLDSA65PrivateKey | mldsa.MLDSA87PrivateKey],
) -> None:
    """Test PKCS#8 round trips and signatures for each ML-DSA variant."""
    private_key = private_key_type.generate()
    serializer = PrivateKeySerializer(private_key)

    loaded_der_key = cast('MldsaPrivateKey', load_der_private_key(serializer.as_pkcs8_der(), password=None))
    loaded_pem_key = cast('MldsaPrivateKey', load_pem_private_key(serializer.as_pkcs8_pem(), password=None))
    message = b'trustpoint-core ML-DSA integration test'

    assert type(loaded_der_key) is type(private_key)
    assert type(loaded_pem_key) is type(private_key)
    signature = private_key.sign(message)
    private_key.public_key().verify(signature, message)
    loaded_der_key.public_key().verify(signature, message)
    loaded_pem_key.public_key().verify(signature, message)


@pytest.mark.parametrize(
    'private_key_type',
    [mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey],
)
def test_mldsa_unsupported_private_key_formats(
    private_key_type: type[mldsa.MLDSA44PrivateKey | mldsa.MLDSA65PrivateKey | mldsa.MLDSA87PrivateKey],
) -> None:
    """Test that unsupported legacy private-key formats fail clearly."""
    serializer = PrivateKeySerializer(private_key_type.generate())

    with pytest.raises(TypeError, match='not supported for ML-DSA'):
        serializer.as_pkcs1_der()
    with pytest.raises(TypeError, match='not supported for ML-DSA'):
        serializer.as_pkcs1_pem()
    with pytest.raises(TypeError, match='not supported for ML-DSA'):
        serializer.as_pkcs12()


# Integration tests
def test_mldsa_full_workflow_44() -> None:
    """Test complete ML-DSA-44 workflow from generation to serialization."""
    # Generate key pair
    private_key = mldsa.MLDSA44PrivateKey.generate()
    public_key = private_key.public_key()

    # Test OID detection
    algo_oid = PublicKeyAlgorithmOid.from_public_key(public_key)
    assert algo_oid == PublicKeyAlgorithmOid.ML_DSA_44

    # Test PublicKeyInfo
    pub_key_info = PublicKeyInfo.from_public_key(public_key)
    assert str(pub_key_info) == 'ML-DSA-44'

    # Test key generation from PublicKeyInfo
    new_private_key = KeyPairGenerator.generate_key_pair_for_public_key_info(pub_key_info)
    assert isinstance(new_private_key, mldsa.MLDSA44PrivateKey)

    # Test serialization
    serializer = PrivateKeySerializer(private_key)
    assert serializer.as_crypto() == private_key

    # Test PrivateKeyReference
    key_ref = PrivateKeyReference.from_private_key(private_key)
    assert key_ref.is_software()


def test_mldsa_full_workflow_65() -> None:
    """Test complete ML-DSA-65 workflow from generation to serialization."""
    # Generate key pair
    private_key = mldsa.MLDSA65PrivateKey.generate()
    public_key = private_key.public_key()

    # Test OID detection
    algo_oid = PublicKeyAlgorithmOid.from_public_key(public_key)
    assert algo_oid == PublicKeyAlgorithmOid.ML_DSA_65

    # Test PublicKeyInfo
    pub_key_info = PublicKeyInfo.from_public_key(public_key)
    assert str(pub_key_info) == 'ML-DSA-65'

    # Test AlgorithmIdentifier
    algo_id = AlgorithmIdentifier.ML_DSA_65
    assert algo_id.public_key_algo_oid == PublicKeyAlgorithmOid.ML_DSA_65


def test_mldsa_full_workflow_87() -> None:
    """Test complete ML-DSA-87 workflow from generation to serialization."""
    # Generate key pair
    private_key = mldsa.MLDSA87PrivateKey.generate()
    public_key = private_key.public_key()

    # Test OID detection
    algo_oid = PublicKeyAlgorithmOid.from_public_key(public_key)
    assert algo_oid == PublicKeyAlgorithmOid.ML_DSA_87

    # Test PublicKeyInfo
    pub_key_info = PublicKeyInfo.from_public_key(public_key)
    assert str(pub_key_info) == 'ML-DSA-87'

    # Test AlgorithmIdentifier
    algo_id = AlgorithmIdentifier.ML_DSA_87
    assert algo_id.public_key_algo_oid == PublicKeyAlgorithmOid.ML_DSA_87
