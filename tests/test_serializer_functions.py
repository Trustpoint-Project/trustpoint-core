import pytest
from cryptography.hazmat.primitives._serialization import BestAvailableEncryption, NoEncryption
import trustpoint_core.serializer as serializer
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey , RSAPrivateKey
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12KeyAndCertificates
from trustpoint_core.serializer import PrivateKeySerializer, PublicKeySerializer
from trustpoint_core.serializer import CertificateSerializer , CertificateCollectionSerializer





@pytest.fixture
def rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

@pytest.fixture
def generate_certificate():
    """Fixture to generate a self-signed certificate for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Test Certificate")
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key, algorithm=hashes.SHA256())
    )

    return certificate, private_key
@pytest.fixture
def generate_certificates():
    """Fixture to generate multiple self-signed certificates for testing."""
    certificates = []
    for i in range(3):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, f"Test Certificate {i}")
        ])

        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, algorithm=hashes.SHA256())
        )

        certificates.append(certificate)

    return certificates


def test_load_pkc12():
    with open('rsa-long.p12', 'rb') as f:
        p12_data = f.read()
    password = b'testing321'
    result = serializer.load_pkcs12_bytes(p12_data, password)

    assert result is not None
    assert isinstance(result, PKCS12KeyAndCertificates)


def test_load_pkcs12_invalid_p12Type():
    with pytest.raises(TypeError):
        serializer.load_pkcs12_bytes('', b'testing321')




def test_load_pkcs12_invalid_passwordType():
    with open('rsa-long.p12', 'rb') as f:
        p12_data = f.read()
    with pytest.raises(TypeError):
        serializer.load_pkcs12_bytes(p12_data, "1234")


def test_load_pkcs12_invalid_passwordOrP12file():
    with pytest.raises(ValueError):
        serializer.load_pkcs12_bytes(b'', b'')

def test_load_pkcs12_corrupt_data():
    with pytest.raises(ValueError, match="Failed to load PKCS#12 bytes"):
        serializer.load_pkcs12_bytes(b'\x00\x01\x02', b'testing321')



def test_get_encryption_algorithm_invalidType():
    with pytest.raises(TypeError):
        result = serializer.get_encryption_algorithm(' ')

def test_get_encryption_algorithme_validType():
    result = serializer.get_encryption_algorithm(b'testing321')
    assert isinstance(result, BestAvailableEncryption)

def test_get_encryption_algorithm_zero():
    result = serializer.get_encryption_algorithm(None)
    assert isinstance(result, NoEncryption)

def test_get_encryption_algorithm_empty_password():
    result = serializer.get_encryption_algorithm(b'')
    assert isinstance(result, NoEncryption)






def test_init_valid_key(rsa_keypair):
    _, public_key = rsa_keypair
    serializer = PublicKeySerializer(public_key)
    assert serializer.as_crypto() == public_key

def test_init_invalid_key():
    with pytest.raises(TypeError, match="Expected a public key object"):
        PublicKeySerializer("invalid_key")


def test_from_der(rsa_keypair):
    _, public_key = rsa_keypair
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    serializer = PublicKeySerializer.from_der(der_bytes)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)


def test_from_der_invalid():
    with pytest.raises(ValueError, match="Failed to load the public key in DER format"):
        PublicKeySerializer.from_der(b"\x00\x01\x02")


def test_from_pem(rsa_keypair):
    _, public_key = rsa_keypair
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    serializer = PublicKeySerializer.from_pem(pem_bytes)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)


def test_from_pem_invalid():
    with pytest.raises(ValueError, match="Failed to load the public key in PEM format"):
        PublicKeySerializer.from_pem(b"INVALID PEM DATA")


def test_from_private_key(rsa_keypair):
    private_key, _ = rsa_keypair
    serializer = PublicKeySerializer.from_private_key(private_key)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)


def test_from_private_key_invalid():
    with pytest.raises(TypeError, match="Expected a private key object"):
        PublicKeySerializer.from_private_key("invalid_private_key")

def test_from_private_key_with_public_key(rsa_keypair):
    _, public_key = rsa_keypair
    with pytest.raises(TypeError, match="Expected a private key object"):
        PublicKeySerializer.from_private_key(public_key)



def test_from_certificate(rsa_keypair):
    _, public_key = rsa_keypair

   
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"Test Certificate")
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key=rsa_keypair[0], algorithm=hashes.SHA256())
    )

    serializer = PublicKeySerializer.from_certificate(certificate)
    assert isinstance(serializer.as_crypto(), RSAPublicKey)



def test_from_certificate_invalid():
    with pytest.raises(TypeError, match="Expected a certificate object"):
        PublicKeySerializer.from_certificate("invalid_certificate")


def test_as_der(rsa_keypair):
    _, public_key = rsa_keypair
    serializer = PublicKeySerializer(public_key)

    der_bytes = serializer.as_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_as_pem(rsa_keypair):
    _, public_key = rsa_keypair
    serializer = PublicKeySerializer(public_key)

    pem_bytes = serializer.as_pem()
    assert isinstance(pem_bytes, bytes)
    assert b"-----BEGIN PUBLIC KEY-----" in pem_bytes


#Here Starts Test Cases for PrivateKeySerializer

def test_private_key_serializer_init(rsa_keypair):

    private_key, _ = rsa_keypair
    serializer = PrivateKeySerializer(private_key)
    assert serializer.as_crypto() == private_key


def test_private_key_serializer_invalid_init():

    with pytest.raises(TypeError, match="Expected a private key object"):
        PrivateKeySerializer("invalid_private_key")




def test_from_pem(rsa_keypair):

    private_key, _ = rsa_keypair
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    serializer = PrivateKeySerializer.from_pem(pem_bytes)
    assert isinstance(serializer.as_crypto(), RSAPrivateKey)


def test_from_pem_invalid():

    with pytest.raises(ValueError, match="Failed to load the private key in PEM format"):
        PrivateKeySerializer.from_pem(b"INVALID PEM DATA")


def test_from_pem_wrong_type():

    with pytest.raises(TypeError, match="Expected private_key to be a bytes object"):
        PrivateKeySerializer.from_pem(12345)




def test_from_der(rsa_keypair):

    private_key, _ = rsa_keypair
    der_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    serializer = PrivateKeySerializer.from_der(der_bytes)
    assert isinstance(serializer.as_crypto(), RSAPrivateKey)


def test_from_der_invalid():

    with pytest.raises(ValueError, match="Failed to load the private key in DER format"):
        PrivateKeySerializer.from_der(b"\x00\x01\x02")


def test_from_der_wrong_type():

    with pytest.raises(TypeError, match="Expected private_key to be a bytes object"):
        PrivateKeySerializer.from_der(12345)




def test_from_pkcs12_bytes(rsa_keypair):


    private_key, _ = rsa_keypair
    pkcs12_bytes = pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=private_key,
        cert=None,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )

    serializer = PrivateKeySerializer.from_pkcs12_bytes(pkcs12_bytes)
    assert isinstance(serializer.as_crypto(), RSAPrivateKey)


def test_from_pkcs12_invalid():

    with pytest.raises(ValueError, match="Failed to load PKCS#12 bytes"):
        PrivateKeySerializer.from_pkcs12_bytes(b" ")



def test_as_pkcs1_der(rsa_keypair):

    private_key, _ = rsa_keypair
    serializer = PrivateKeySerializer(private_key)

    der_bytes = serializer.as_pkcs1_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_as_pkcs1_pem(rsa_keypair):

    private_key, _ = rsa_keypair
    serializer = PrivateKeySerializer(private_key)

    pem_bytes = serializer.as_pkcs1_pem()
    assert isinstance(pem_bytes, bytes)
    assert b"-----BEGIN RSA PRIVATE KEY-----" in pem_bytes


def test_as_pkcs8_der(rsa_keypair):

    private_key, _ = rsa_keypair
    serializer = PrivateKeySerializer(private_key)

    der_bytes = serializer.as_pkcs8_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_as_pkcs8_pem(rsa_keypair):

    private_key, _ = rsa_keypair
    serializer = PrivateKeySerializer(private_key)

    pem_bytes = serializer.as_pkcs8_pem()
    assert isinstance(pem_bytes, bytes)
    assert b"-----BEGIN PRIVATE KEY-----" in pem_bytes


def test_as_pkcs12(rsa_keypair):

    private_key, _ = rsa_keypair
    serializer = PrivateKeySerializer(private_key)

    pkcs12_bytes = serializer.as_pkcs12()
    assert isinstance(pkcs12_bytes, bytes)
    assert len(pkcs12_bytes) > 0



def test_public_key_serializer(rsa_keypair):

    private_key, public_key = rsa_keypair
    serializer = PrivateKeySerializer(private_key)

    public_serializer = serializer.public_key_serializer
    assert isinstance(public_serializer, PublicKeySerializer)
    assert public_serializer.as_crypto() == public_key


### from here pytest for certificate serializer ###



def test_certificate_serializer_init(generate_certificate):

    certificate, _ = generate_certificate
    serializer = CertificateSerializer(certificate)
    assert serializer.as_crypto() == certificate


def test_certificate_serializer_invalid_init():

    with pytest.raises(TypeError, match="Expected a certificate object"):
        CertificateSerializer("invalid_certificate")



def test_from_pem(generate_certificate):

    certificate, _ = generate_certificate
    pem_bytes = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    serializer = CertificateSerializer.from_pem(pem_bytes)
    assert serializer.as_crypto() == certificate


def test_from_pem_invalid():

    with pytest.raises(ValueError, match="Failed to load the provided certificate in PEM format"):
        CertificateSerializer.from_pem(b"INVALID PEM DATA")


def test_from_pem_wrong_type():

    with pytest.raises(TypeError, match="Expected the certificate to be a bytes object"):
        CertificateSerializer.from_pem(12345)



def test_from_der(generate_certificate):

    certificate, _ = generate_certificate
    der_bytes = certificate.public_bytes(encoding=serialization.Encoding.DER)

    serializer = CertificateSerializer.from_der(der_bytes)
    assert serializer.as_crypto() == certificate


def test_from_der_invalid():

    with pytest.raises(ValueError, match="Failed to load the provided certificate in DER format"):
        CertificateSerializer.from_der(b"\x00\x01\x02")


def test_from_der_wrong_type():

    with pytest.raises(TypeError, match="Expected the certificate to be a bytes object"):
        CertificateSerializer.from_der(12345)



def test_as_pem(generate_certificate):

    certificate, _ = generate_certificate
    serializer = CertificateSerializer(certificate)

    pem_bytes = serializer.as_pem()
    assert isinstance(pem_bytes, bytes)
    assert b"-----BEGIN CERTIFICATE-----" in pem_bytes


def test_as_der(generate_certificate):

    certificate, _ = generate_certificate
    serializer = CertificateSerializer(certificate)

    der_bytes = serializer.as_der()
    assert isinstance(der_bytes, bytes)
    assert len(der_bytes) > 0


def test_as_pkcs7_pem(generate_certificate):

    certificate, _ = generate_certificate
    serializer = CertificateSerializer(certificate)

    pkcs7_pem_bytes = serializer.as_pkcs7_pem()
    assert isinstance(pkcs7_pem_bytes, bytes)
    assert len(pkcs7_pem_bytes) > 0


def test_as_pkcs7_der(generate_certificate):

    certificate, _ = generate_certificate
    serializer = CertificateSerializer(certificate)

    pkcs7_der_bytes = serializer.as_pkcs7_der()
    assert isinstance(pkcs7_der_bytes, bytes)
    assert len(pkcs7_der_bytes) > 0



def test_public_key(generate_certificate):

    certificate, _ = generate_certificate
    serializer = CertificateSerializer(certificate)
    public_key = serializer.public_key
    assert isinstance(public_key, rsa.RSAPublicKey)


def test_public_key_serializer(generate_certificate):

    certificate, _ = generate_certificate
    serializer = CertificateSerializer(certificate)

    public_key_serializer = serializer.public_key_serializer
    assert isinstance(public_key_serializer, PublicKeySerializer)
    assert isinstance(public_key_serializer.as_crypto(), rsa.RSAPublicKey)



### From here test starts for CertificateCollectionSerializer








def test_certificate_collection_serializer_init(generate_certificates):

    serializer = CertificateCollectionSerializer(generate_certificates)
    assert len(serializer.as_crypto()) == 3


def test_certificate_collection_serializer_init_empty():

    serializer = CertificateCollectionSerializer([])
    assert len(serializer.as_crypto()) == 0


def test_certificate_collection_serializer_invalid_init():

    with pytest.raises(TypeError):
        CertificateCollectionSerializer("invalid_certificate_list")


def test_certificate_collection_serializer_invalid_cert_object():

    with pytest.raises(TypeError):
        CertificateCollectionSerializer(["invalid_certificate"])



def test_from_list_of_pem(generate_certificates):

    pem_bytes_list = [cert.public_bytes(encoding=serialization.Encoding.PEM) for cert in generate_certificates]
    serializer = CertificateCollectionSerializer.from_list_of_pem(pem_bytes_list)
    assert len(serializer.as_crypto()) == 3


def test_from_list_of_der(generate_certificates):

    der_bytes_list = [cert.public_bytes(encoding=serialization.Encoding.DER) for cert in generate_certificates]
    serializer = CertificateCollectionSerializer.from_list_of_der(der_bytes_list)
    assert len(serializer.as_crypto()) == 3


def test_from_pem(generate_certificates):

    pem_bytes = b"".join(cert.public_bytes(encoding=serialization.Encoding.PEM) for cert in generate_certificates)
    serializer = CertificateCollectionSerializer.from_pem(pem_bytes)
    assert len(serializer.as_crypto()) == 3



def test_from_pem_invalid():

    with pytest.raises(ValueError):
        CertificateCollectionSerializer.from_pem(b"INVALID PEM DATA")


def test_from_der_invalid():

    with pytest.raises(ValueError):
        CertificateCollectionSerializer.from_list_of_der([b"\x00\x01\x02"])



def test_as_pem(generate_certificates):

    serializer = CertificateCollectionSerializer(generate_certificates)
    pem_bytes = serializer.as_pem()
    assert isinstance(pem_bytes, bytes)
    assert b"-----BEGIN CERTIFICATE-----" in pem_bytes


def test_as_der_list(generate_certificates):

    serializer = CertificateCollectionSerializer(generate_certificates)
    der_list = serializer.as_der_list()
    assert isinstance(der_list, list)
    assert len(der_list) == 3


def test_as_pkcs7_pem(generate_certificates):

    serializer = CertificateCollectionSerializer(generate_certificates)
    pkcs7_pem = serializer.as_pkcs7_pem()
    assert isinstance(pkcs7_pem, bytes)
    assert len(pkcs7_pem) > 0


def test_as_pkcs7_der(generate_certificates):

    serializer = CertificateCollectionSerializer(generate_certificates)
    pkcs7_der = serializer.as_pkcs7_der()
    assert isinstance(pkcs7_der, bytes)
    assert len(pkcs7_der) > 0



def test_add_certificate(generate_certificates):

    serializer = CertificateCollectionSerializer(generate_certificates[:2])  
    new_cert = generate_certificates[2]
    new_collection = serializer + new_cert

    assert len(new_collection.as_crypto()) == 3  


def test_add_certificate_collection(generate_certificates):
    serializer1 = CertificateCollectionSerializer(generate_certificates[:2])
    serializer2 = CertificateCollectionSerializer([generate_certificates[2]])

    new_collection = serializer1 + serializer2
    assert len(new_collection.as_crypto()) == 3


def test_len_function(generate_certificates):
    serializer = CertificateCollectionSerializer(generate_certificates)
    assert len(serializer) == 3

