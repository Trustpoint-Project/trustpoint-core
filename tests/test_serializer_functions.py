import pytest
from cryptography.hazmat.primitives._serialization import BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12KeyAndCertificates

import trustpoint_core.serializer as serializer




from cryptography.hazmat.primitives.serialization import pkcs12


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
    with open('rsa-long.p12', 'rb') as f:
        p12_data = f.read()
    with pytest.raises(ValueError):
        serializer.load_pkcs12_bytes(b'', b'')



def test_get_encryption_algorithm_invalidType():
    with pytest.raises(TypeError):
        result = serializer.get_encryption_algorithm(' ')

def test_get_encryption_algorithme_validType():
    result = serializer.get_encryption_algorithm(b'testing321')
    assert isinstance(result, BestAvailableEncryption)

def test_get_encryption_algorithme_Zero():
    result = serializer.get_encryption_algorithm(None)
    assert isinstance(result, NoEncryption)