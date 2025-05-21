"""OID Enums and Public Key / SignatureSuite wrappers."""

from __future__ import annotations

import enum
import typing
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from trustpoint_core.key_types import PrivateKey, PublicKey

if TYPE_CHECKING:
    from typing import Self

    from cryptography import x509


RSA_MIN_KEY_SIZE = 2048
EC_MIN_KEY_SIZE = 128


@dataclass(frozen=True)
class NameOidData:
    """The Name OID Data class holding all of the information."""

    dotted_string: str
    abbreviation: str | None
    full_name: str
    verbose_name: str


class NameOid(enum.Enum):
    """Name OID Enum holding OID metadata as dataclass instances."""

    OBJECT_CLASS = NameOidData('2.5.4.0', None, 'objectClass', 'Object Class')
    ALIASED_ENTRY_NAME = NameOidData('2.5.4.1', None, 'aliasedEntryName', 'Aliased Entry Name')
    KNOWLEDGE_INFORMATION = NameOidData('2.5.4.2', None, 'knowledgeInformation', 'Knowledge Information')
    COMMON_NAME = NameOidData('2.5.4.3', 'CN', 'commonName', 'Common Name')
    SURNAME = NameOidData('2.5.4.4', 'SN', 'Surname', 'Surname')
    SERIAL_NUMBER = NameOidData('2.5.4.5', None, 'serialNumber', 'Serial Number')
    COUNTRY_NAME = NameOidData('2.5.4.6', 'C', 'countryName', 'Country Name')
    LOCALITY_NAME = NameOidData('2.5.4.7', 'L', 'localityName', 'Locality Name')
    STATE_OR_PROVINCE_NAME = NameOidData('2.5.4.8', 'ST', 'stateOrProvinceName', 'State or Province Name')
    STREET_ADDRESS = NameOidData('2.5.4.9', None, 'streetAddress', 'Street Address')
    ORGANIZATION_NAME = NameOidData('2.5.4.10', 'O', 'organizationName', 'Organization Name')
    ORGANIZATIONAL_UNIT_NAME = NameOidData('2.5.4.11', 'OU', 'organizationalUnitName', 'Organizational Unit Name')
    TITLE = NameOidData('2.5.4.12', 'T', 'title', 'Title')
    DESCRIPTION = NameOidData('2.5.4.13', None, 'description', 'Description')
    SEARCH_GUIDE = NameOidData('2.5.4.14', None, 'searchGuide', 'Search Guide')
    BUSINESS_CATEGORY = NameOidData('2.5.4.15', None, 'businessCategory', 'Business Category')
    POSTAL_ADDRESS = NameOidData('2.5.4.16', None, 'postalAddress', 'Postal Address')
    POSTAL_CODE = NameOidData('2.5.4.17', None, 'postalCode', 'Postal Code')
    POST_OFFICE_BOX = NameOidData('2.5.4.18', None, 'postOfficeBox', 'Post Office Box')
    PHYSICAL_DELIVERY_OFFICE_NAME = NameOidData(
        '2.5.4.19', None, 'physicalDeliveryOfficeName', 'Physical Delivery Office Name'
    )
    TELEPHONE_NUMBER = NameOidData('2.5.4.20', None, 'telephoneNumber', 'Telephone Number')
    TELEX_NUMBER = NameOidData('2.5.4.21', None, 'telexNumber', 'Telex Number')
    TELEX_TERMINAL_IDENTIFIER = NameOidData('2.5.4.22', None, 'telexTerminalIdentifier', 'Telex Terminal Identifier')
    FACSIMILE_TELEPHONE_NUMBER = NameOidData('2.5.4.23', None, 'facsimileTelephoneNumber', 'Facsimile Telephone Number')
    X121_ADDRESS = NameOidData('2.5.4.24', None, 'x121Address', 'X121 Address')
    INTERNATIONAL_ISD_NUMBER = NameOidData('2.5.4.25', None, 'internationalISDNumber', 'International ISD Number')
    REGISTERED_ADDRESS = NameOidData('2.5.4.26', None, 'registeredAddress', 'Registered Address')
    DESTINATION_INDICATOR = NameOidData('2.5.4.27', None, 'destinationIndicator', 'Destination Indicator')
    PREFERRED_DELIVERY_METHOD = NameOidData('2.5.4.28', None, 'preferredDeliveryMethod', 'Preferred Delivery Method')
    PRESENTATION_ADDRESS = NameOidData('2.5.4.29', None, 'presentationAddress', 'Presentation Address')
    SUPPORTED_APPLICATION_CONTEXT = NameOidData(
        '2.5.4.30', None, 'supportedApplicationContext', 'Supported Application Context'
    )
    MEMBER = NameOidData('2.5.4.31', None, 'member', 'Member')
    OWNER = NameOidData('2.5.4.32', None, 'owner', 'Owner')
    ROLE_OCCUPANT = NameOidData('2.5.4.33', None, 'roleOccupant', 'Role Occupant')
    SEE_ALSO = NameOidData('2.5.4.34', None, 'seeAlso', 'See Also')
    USER_PASSWORD = NameOidData('2.5.4.35', None, 'userPassword', 'User Password')
    USER_CERTIFICATE = NameOidData('2.5.4.36', None, 'userCertificate', 'User Certificate')
    CA_CERTIFICATE = NameOidData('2.5.4.37', None, 'cACertificate', 'CA Certificate')
    AUTHORITY_REVOCATION_LIST = NameOidData('2.5.4.38', None, 'authorityRevocationList', 'Authority Revocation List')
    CERTIFICATE_REVOCATION_LIST = NameOidData(
        '2.5.4.39', None, 'certificateRevocationList', 'Certificate Revocation List'
    )
    CROSS_CERTIFICATE_PAIR = NameOidData('2.5.4.40', None, 'crossCertificatePair', 'Cross Certificate Pair')
    NAME = NameOidData('2.5.4.41', None, 'name', 'Name')
    GIVEN_NAME = NameOidData('2.5.4.42', 'GN', 'givenName', 'Given Name')
    INITIALS = NameOidData('2.5.4.43', None, 'initials', 'Initials')
    GENERATION_QUALIFIER = NameOidData('2.5.4.44', None, 'generationQualifier', 'Generation Qualifier')
    X500_UNIQUE_IDENTIFIER = NameOidData('2.5.4.45', None, 'x500UniqueIdentifier', 'X500 Unique Identifier')
    DN_QUALIFIER = NameOidData('2.5.4.46', None, 'dnQualifier', 'DN Qualifier')
    ENHANCED_SEARCH_GUIDE = NameOidData('2.5.4.47', None, 'enhancedSearchGuide', 'Enhanced Search Guide')
    PROTOCOL_INFORMATION = NameOidData('2.5.4.48', None, 'protocolInformation', 'Protocol Information')
    DISTINGUISHED_NAME = NameOidData('2.5.4.49', None, 'distinguishedName', 'Distinguished Name')
    UNIQUE_MEMBER = NameOidData('2.5.4.50', None, 'uniqueMember', 'Unique Member')
    HOUSE_IDENTIFIER = NameOidData('2.5.4.51', None, 'houseIdentifier', 'House Identifier')
    SUPPORTED_ALGORITHMS = NameOidData('2.5.4.52', None, 'supportedAlgorithms', 'Supported Algorithms')
    DELTA_REVOCATION_LIST = NameOidData('2.5.4.53', None, 'deltaRevocationList', 'Delta Revocation List')
    DMD_NAME = NameOidData('2.5.4.54', None, 'dmdName', 'DMD Name')
    CLEARANCE = NameOidData('2.5.4.55', None, 'clearance', 'Clearance')
    DEFAULT_DIR_QOP = NameOidData('2.5.4.56', None, 'defaultDirQop', 'Default DIR QOP')
    ATTRIBUTE_INTEGRITY_INFO = NameOidData('2.5.4.57', None, 'attributeIntegrityInfo', 'Attribute Integrity Info')
    ATTRIBUTE_CERTIFICATE = NameOidData('2.5.4.58', None, 'attributeCertificate', 'Attribute Certificate')
    ATTRIBUTE_CERTIFICATE_REVOCATION_LIST = NameOidData(
        '2.5.4.59', None, 'attributeCertificateRevocationList', 'Attribute Certificate Revocation List'
    )
    CONF_KEY_INFO = NameOidData('2.5.4.60', None, 'confKeyInfo', 'Conf Key Info')
    AA_CERTIFICATE = NameOidData('2.5.4.61', None, 'aACertificate', 'AA Certificate')
    ATTRIBUTE_DESCRIPTOR_CERTIFICATE = NameOidData(
        '2.5.4.62', None, 'attributeDescriptorCertificate', 'Attribute Descriptor Certificate'
    )
    ATTRIBUTE_AUTHORITY_REVOCATION_LIST = NameOidData(
        '2.5.4.63', None, 'attributeAuthorityRevocationList', 'Attribute Authority Revocation List'
    )
    FAMILY_INFORMATION = NameOidData('2.5.4.64', None, 'familyInformation', 'Family Information')
    PSEUDONYM = NameOidData('2.5.4.65', None, 'pseudonym', 'Pseudonym')
    COMMUNICATIONS_SERVICE = NameOidData('2.5.4.66', None, 'communicationsService', 'Communications Service')
    COMMUNICATIONS_NETWORK = NameOidData('2.5.4.67', None, 'communicationsNetwork', 'Communications Network')
    CERTIFICATION_PRACTICE_STMT = NameOidData(
        '2.5.4.68', None, 'certificationPracticeStmt', 'Certification Practice Statement'
    )
    CERTIFICATE_POLICY = NameOidData('2.5.4.69', None, 'certificatePolicy', 'Certificate Policy')
    PKI_PATH = NameOidData('2.5.4.70', None, 'pkiPath', 'PKI Path')
    PRIVILEGE_POLICY = NameOidData('2.5.4.71', None, 'privilegePolicy', 'Privilege Policy')
    ROLE = NameOidData('2.5.4.72', None, 'role', 'Role')
    PMI_DELEGATION_PATH = NameOidData('2.5.4.73', None, 'pmiDelegationPath', 'PMI Delegation Path')
    PROTECTED_PRIVILEGE_POLICY = NameOidData('2.5.4.74', None, 'protectedPrivilegePolicy', 'Protected Privilege Policy')
    XML_PRIVILEGE_INFO = NameOidData('2.5.4.75', None, 'xMLPrivilegeInfo', 'XML Privilege Info')
    XML_PRIV_POLICY = NameOidData('2.5.4.76', None, 'xmlPrivPolicy', 'XML Privilege Policy')
    UUID_PAIR = NameOidData('2.5.4.77', None, 'uuidPair', 'UUID Pair')
    TAG_OID = NameOidData('2.5.4.78', None, 'tagOid', 'Tag OID')
    UII_FORMAT = NameOidData('2.5.4.79', None, 'uiiFormat', 'UII Format')
    UII_IN_URN = NameOidData('2.5.4.80', None, 'uiiInUrn', 'UII in URN')
    CONTENT_URL = NameOidData('2.5.4.81', None, 'contentUrl', 'Content URL')
    PERMISSION = NameOidData('2.5.4.82', None, 'permission', 'Permission')
    URI = NameOidData('2.5.4.83', None, 'uri', 'Uniform Resource Identifier (URI)')
    PWD_ATTRIBUTE = NameOidData('2.5.4.84', None, 'pwdAttribute', 'Password Attribute')
    USER_PWD = NameOidData('2.5.4.85', None, 'userPwd', 'User Password')
    URN = NameOidData('2.5.4.86', None, 'urn', 'Uniform Resource Name (URN)')
    URL = NameOidData('2.5.4.87', None, 'url', 'Uniform Resource Locator (URL)')
    UTM_COORDINATES = NameOidData('2.5.4.88', None, 'utmCoordinates', 'UTM Coordinates')
    URN_C = NameOidData('2.5.4.89', None, 'urnC', 'Uniform Resource Locator Component (urnC)')
    UII = NameOidData('2.5.4.90', None, 'uii', 'Unique Item Identifier (UII)')
    EPC = NameOidData('2.5.4.91', None, 'epc', 'Electronic Product Code')
    TAG_AFI = NameOidData('2.5.4.92', None, 'tagAfi', 'Tag AFI')
    EPC_FORMAT = NameOidData('2.5.4.93', None, 'epcFormat', 'EPC Format')
    EPC_IN_URN = NameOidData('2.5.4.94', None, 'epcInUrn', 'EPC in URN')
    LDAP_URL = NameOidData('2.5.4.95', None, 'ldapUrl', 'LDAP URL')
    TAG_LOCATION = NameOidData('2.5.4.96', None, 'tagLocation', 'Tag Location')
    ORGANIZATION_IDENTIFIER = NameOidData('2.5.4.97', None, 'organizationIdentifier', 'Organization Identifier')
    COUNTRY_CODE_3C = NameOidData('2.5.4.98', None, 'countryCode3c', 'Country Code 3C (ISO 3166-1 alpha-3)')
    COUNTRY_CODE_3N = NameOidData('2.5.4.99', None, 'countryCode3n', 'Country Code 3N (ISO 3166-1 numeric-3)')
    DNS_NAME = NameOidData('2.5.4.100', None, 'dnsName', 'DNS Name')
    EE_PK_CERTIFICATE_REVOCATION_LIST = NameOidData(
        '2.5.4.101', None, 'eepkCertificateRevocationList', 'End-Entity Public-Key Certificate Revocation List'
    )
    EE_ATTR_CERTIFICATE_REVOCATION_LIST = NameOidData(
        '2.5.4.102', None, 'eeAttrCertificateRevocationList', 'End-Entity Attribute Certificate Revocation List'
    )
    SUPPORTED_PUBLIC_KEY_ALGORITHMS = NameOidData(
        '2.5.4.103', None, 'supportedPublicKeyAlgorithms', 'Supported Public-Key Algorithms'
    )
    INT_EMAIL = NameOidData('2.5.4.104', None, 'intEmail', 'Internationalized Email Address')
    JID = NameOidData('2.5.4.105', None, 'jid', 'Jabber Identifier')
    OBJECT_IDENTIFIER = NameOidData('2.5.4.106', None, 'objectIdentifier', 'Object Identifier')

    # GOST Algorithms
    OGRN = NameOidData('1.2.643.100.1', None, 'ogrn', 'Main State Registration Number of Juridical Entities (OGRN)')
    SNILS = NameOidData('1.2.643.100.3', None, 'snils', 'Individual Insurance Account Number (SNILS)')
    INNLE = NameOidData('1.2.643.100.4', None, 'innle', 'Individual Taxpayer Number of Legal Entity (ITN)')
    OGRN_IP = NameOidData(
        '1.2.643.100.5', None, 'ogrnip', 'Main State Registration Number of Individual Entrepreneurs (OGRN IP)'
    )
    IDENTIFICATION_KIND = NameOidData('1.2.643.100.114', None, 'identificationKind', 'Identification Kind')
    INN = NameOidData('1.2.643.3.131.1.1', None, 'inn', 'Individual Taxpayer Number (ITN, INN)')

    # RFC 2985
    EMAIL_ADDRESS = NameOidData('1.2.840.113549.1.9.1', 'E', 'emailAddress', 'Email Address (Deprecated)')
    UNSTRUCTURED_NAME = NameOidData('1.2.840.113549.1.9.2', None, 'unstructuredName', 'Unstructured Name')
    CONTENT_TYPE = NameOidData('1.2.840.113549.1.9.3', None, 'contentType', 'Content Type')
    UNSTRUCTURED_ADDRESS = NameOidData('1.2.840.113549.1.9.8', None, 'unstructuredAddress', 'Unstructured Address')

    # RFC 3039, RFC 2247, RFC 4519, RFC 5912
    UID = NameOidData('0.9.2342.19200300.100.1.1', 'UID', 'uid', 'User ID (UID)')
    DOMAIN_COMPONENT = NameOidData('0.9.2342.19200300.100.1.25', 'DC', 'domainComponent', 'Domain Component')

    # Microsoft Jurisdiction of Incorporation
    JURISDICTION_OF_INCORPORATION_LOCALITY_NAME = NameOidData(
        '1.3.6.1.4.1.311.60.2.1.1',
        None,
        'jurisdictionOfIncorporationLocalityName',
        'Jurisdiction Of Incorporation Locality Name',
    )
    JURISDICTION_OF_INCORPORATION_STATE_OR_PROVINCE_NAME = NameOidData(
        '1.3.6.1.4.1.311.60.2.1.2',
        None,
        'jurisdictionOfIncorporationStateOrProvinceName',
        'Jurisdiction Of Incorporation State Or Province Name',
    )
    JURISDICTION_OF_INCORPORATION_COUNTRY_NAME = NameOidData(
        '1.3.6.1.4.1.311.60.2.1.3',
        None,
        'jurisdictionOfIncorporationCountryName',
        'Jurisdiction Of Incorporation Country Name',
    )

    # Spain related
    DNI = NameOidData('1.3.6.1.4.1.19126.3', None, 'dni', 'DNI - National identity document (Spain)')
    NSS = NameOidData('1.3.6.1.4.1.19126.4', None, 'nss', 'NSS - Social Security Number (Spain)')
    CIRCULATION_PERMIT_NUMBER = NameOidData(
        '1.3.6.1.4.1.19126.5', None, 'circulationPermitNumber', 'Circulation Permit Number (Spain)'
    )
    CIF = NameOidData('1.3.6.1.4.1.19126.21', None, 'cif', 'CIF - Tax Identification Code (Spain)')
    NIF = NameOidData('2.16.724.4.307', None, 'nif', 'NIF - Fiscal Identification Number (Spain)')

    @property
    def dotted_string(self) -> str:
        """Return the dotted string OID.

        Returns:
            The dotted string OID.
        """
        return self.value.dotted_string

    @property
    def abbreviation(self) -> str | None:
        """Return the abbreviation for the NameOid, if any.

        Returns:
            The abbreviation, or None if not defined.
        """
        return self.value.abbreviation

    @property
    def full_name(self) -> str:
        """Return the full name for the NameOid.

        Returns:
            The full name.
        """
        return self.value.full_name

    @property
    def verbose_name(self) -> str:
        """Return the verbose name for display.

        Returns:
            The verbose name.
        """
        return self.value.verbose_name

    @classmethod
    def from_dotted_string(cls, dotted: str) -> Self:
        """Return enum member matching a dotted_string."""
        for member in cls:
            if member.value.dotted_string == dotted:
                return member
        err_msg = f'No NameOid with dotted_string={dotted!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_abbreviation(cls, abbr: str | None) -> Self:
        """Return enum member matching an abbreviation. Raises if no or multiple matches."""
        matches = [member for member in cls if member.value.abbreviation == abbr]
        if not matches:
            err_msg = f'No NameOid with abbreviation={abbr!r}'
            raise ValueError(err_msg)
        if len(matches) > 1:
            err_msg = f'Multiple NameOid entries with abbreviation={abbr!r}'
            raise ValueError(err_msg)
        return matches[0]

    @classmethod
    def from_full_name(cls, full: str) -> Self:
        """Return enum member matching a full_name."""
        for member in cls:
            if member.value.full_name == full:
                return member
        err_msg = f'No NameOid with full_name={full!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_verbose_name(cls, verbose: str) -> Self:
        """Return enum member matching a verbose_name."""
        for member in cls:
            if member.value.verbose_name == verbose:
                return member
        err_msg = f'No NameOid with verbose_name={verbose!r}'
        raise ValueError(err_msg)


@dataclass(frozen=True)
class CertificateExtensionOidData:
    """The Certificate Extension OID Data class holding all of the information."""

    dotted_string: str
    verbose_name: str


class CertificateExtensionOid(enum.Enum):
    """Certificate Extension OID Enum holding extension metadata as dataclass instances and lookup helpers."""

    SUBJECT_DIRECTORY_ATTRIBUTES = CertificateExtensionOidData('2.5.29.9', 'Subject Directory Attributes')
    SUBJECT_KEY_IDENTIFIER = CertificateExtensionOidData('2.5.29.14', 'Subject Key Identifier')
    KEY_USAGE = CertificateExtensionOidData('2.5.29.15', 'Key Usage')
    SUBJECT_ALTERNATIVE_NAME = CertificateExtensionOidData('2.5.29.17', 'Subject Alternative Name')
    ISSUER_ALTERNATIVE_NAME = CertificateExtensionOidData('2.5.29.18', 'Issuer Alternative Name')
    BASIC_CONSTRAINTS = CertificateExtensionOidData('2.5.29.19', 'Basic Constraints')
    NAME_CONSTRAINTS = CertificateExtensionOidData('2.5.29.30', 'Name Constraints')
    CRL_DISTRIBUTION_POINTS = CertificateExtensionOidData('2.5.29.31', 'CRL Distribution Points')
    CERTIFICATE_POLICIES = CertificateExtensionOidData('2.5.29.32', 'Certificate Policies')
    POLICY_MAPPINGS = CertificateExtensionOidData('2.5.29.33', 'Policy Mappings')
    AUTHORITY_KEY_IDENTIFIER = CertificateExtensionOidData('2.5.29.35', 'Authority Key Identifier')
    POLICY_CONSTRAINTS = CertificateExtensionOidData('2.5.29.36', 'Policy Constraints')
    EXTENDED_KEY_USAGE = CertificateExtensionOidData('2.5.29.37', 'Extended Key Usage')
    FRESHEST_CRL = CertificateExtensionOidData('2.5.29.46', 'Freshest CRL')
    INHIBIT_ANY_POLICY = CertificateExtensionOidData('2.5.29.54', 'Inhibit Any Policy')
    ISSUING_DISTRIBUTION_POINT = CertificateExtensionOidData('2.5.29.28', 'Issuing Distribution Point')
    AUTHORITY_INFORMATION_ACCESS = CertificateExtensionOidData('1.3.6.1.5.5.7.1.1', 'Authority Information Access')
    SUBJECT_INFORMATION_ACCESS = CertificateExtensionOidData('1.3.6.1.5.5.7.1.11', 'Subject Information Access')
    OCSP_NO_CHECK = CertificateExtensionOidData('1.3.6.1.5.5.7.48.1.5', 'OCSP No Check')
    TLS_FEATURE = CertificateExtensionOidData('1.3.6.1.5.5.7.1.24', 'TLS Feature')
    CRL_NUMBER = CertificateExtensionOidData('2.5.29.20', 'CRL Number')
    DELTA_CRL_INDICATOR = CertificateExtensionOidData('2.5.29.27', 'Delta CRL Indicator')
    PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS = CertificateExtensionOidData(
        '1.3.6.1.4.1.11129.2.4.2',
        'Precert Signed Certificate Timestamps',
    )
    PRECERT_POISON = CertificateExtensionOidData('1.3.6.1.4.1.11129.2.4.3', 'Precert Poison')
    SIGNED_CERTIFICATE_TIMESTAMPS = CertificateExtensionOidData(
        '1.3.6.1.4.1.11129.2.4.5',
        'Signed Certificate Timestamps',
    )
    MS_CERTIFICATE_TEMPLATE = CertificateExtensionOidData('1.3.6.1.4.1.311.21.7', 'Microsoft Certificate Template')

    @property
    def dotted_string(self) -> str:
        """Return the dotted string OID.

        Returns:
            The dotted string OID.
        """
        return self.value.dotted_string

    @property
    def verbose_name(self) -> str:
        """Return the verbose name for display.

        Returns:
            The verbose name.
        """
        return self.value.verbose_name

    @classmethod
    def from_dotted_string(cls, dotted: str) -> Self:
        """Return enum member matching a dotted_string."""
        for m in cls:
            if m.value.dotted_string == dotted:
                return m
        err_msg = f'No CertificateExtensionOid with dotted_string={dotted!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_verbose_name(cls, verbose: str) -> Self:
        """Return enum member matching a verbose_name."""
        for m in cls:
            if m.value.verbose_name == verbose:
                return m
        err_msg = f'No CertificateExtensionOid with verbose_name={verbose!r}'
        raise ValueError(err_msg)


@dataclass(frozen=True)
class NamedCurveData:
    """The Named Curve Data class holding all of the information."""

    dotted_string: str
    verbose_name: str
    key_size: int
    curve: type[ec.EllipticCurve] | None
    ossl_curve_name: str


class NamedCurve(enum.Enum):
    """Named Curve Enum holding curve metadata as dataclass instances and lookup helpers."""

    NONE = NamedCurveData('None', 'None', 0, None, '')
    SECP192R1 = NamedCurveData('1.2.840.10045.3.1.1', 'SECP192R1', 192, ec.SECP192R1, 'prime192v1')
    SECP224R1 = NamedCurveData('1.3.132.0.33', 'SECP224R1', 224, ec.SECP224R1, 'secp224r1')
    SECP256K1 = NamedCurveData('1.3.132.0.10', 'SECP256K1', 256, ec.SECP256K1, 'secp256k1')
    SECP256R1 = NamedCurveData('1.2.840.10045.3.1.7', 'SECP256R1', 256, ec.SECP256R1, 'prime256v1')
    SECP384R1 = NamedCurveData('1.3.132.0.34', 'SECP384R1', 384, ec.SECP384R1, 'secp384r1')
    SECP521R1 = NamedCurveData('1.3.132.0.35', 'SECP521R1', 521, ec.SECP521R1, 'secp521r1')
    BRAINPOOLP256R1 = NamedCurveData(
        '1.3.36.3.3.2.8.1.1.7',
        'BRAINPOOLP256R1',
        256,
        ec.BrainpoolP256R1,
        'brainpoolP256r1',
    )
    BRAINPOOLP384R1 = NamedCurveData(
        '1.3.36.3.3.2.8.1.1.11',
        'BRAINPOOLP384R1',
        384,
        ec.BrainpoolP384R1,
        'brainpoolP384r1',
    )
    BRAINPOOLP512R1 = NamedCurveData(
        '1.3.36.3.3.2.8.1.1.13',
        'BRAINPOOLP512R1',
        512,
        ec.BrainpoolP512R1,
        'brainpoolP512r1',
    )
    SECT163K1 = NamedCurveData('1.3.132.0.1', 'SECT163K1', 163, ec.SECT163K1, 'sect163r1')
    SECT163R2 = NamedCurveData('1.3.132.0.15', 'SECT163R2', 163, ec.SECT163R2, 'sect163r2')
    SECT233K1 = NamedCurveData('1.3.132.0.26', 'SECT233K1', 233, ec.SECT233K1, 'sect233k1')
    SECT233R1 = NamedCurveData('1.3.132.0.27', 'SECT233R1', 233, ec.SECT233R1, 'sect233r1')
    SECT283K1 = NamedCurveData('1.3.132.0.16', 'SECT283K1', 283, ec.SECT283K1, 'sect283k1')
    SECT283R1 = NamedCurveData('1.3.132.0.17', 'SECT283R1', 283, ec.SECT283R1, 'sect283r1')
    SECT409K1 = NamedCurveData('1.3.132.0.36', 'SECT409K1', 409, ec.SECT409K1, 'sect409k1')
    SECT409R1 = NamedCurveData('1.3.132.0.37', 'SECT409R1', 409, ec.SECT409R1, 'sect409r1')
    SECT571K1 = NamedCurveData('1.3.132.0.38', 'SECT571K1', 571, ec.SECT571K1, 'sect571k1')
    SECT571R1 = NamedCurveData('1.3.132.0.39', 'SECT571R1', 571, ec.SECT571R1, 'sect571r1')

    @property
    def dotted_string(self) -> str:
        """Return the dotted string OID.

        Returns:
            The dotted string OID.
        """
        return self.value.dotted_string

    @property
    def verbose_name(self) -> str:
        """Return the verbose name for display.

        Returns:
            The verbose name.
        """
        return self.value.verbose_name

    @property
    def key_size(self) -> int:
        """Return the key size of the curve.

        Returns:
            The key size in bits.
        """
        return self.value.key_size

    @property
    def curve(self) -> type[ec.EllipticCurve] | None:
        """Return the Python cryptography EllipticCurve class.

        Returns:
            The curve class, or None.
        """
        return self.value.curve

    @property
    def ossl_curve_name(self) -> str:
        """Return the OpenSSL curve name.

        Returns:
            The OpenSSL curve name string.
        """
        return self.value.ossl_curve_name

    @classmethod
    def from_dotted_string(cls, dotted: str) -> Self:
        """Return enum member matching a dotted_string."""
        for m in cls:
            if m.value.dotted_string == dotted:
                return m
        err_msg = f'No NamedCurve with dotted_string={dotted!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_verbose_name(cls, verbose: str) -> Self:
        """Return enum member matching a verbose_name."""
        for m in cls:
            if m.value.verbose_name == verbose:
                return m
        err_msg = f'No NamedCurve with verbose_name={verbose!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_curve(cls, curve: type[ec.EllipticCurve] | None) -> Self:
        """Return enum member matching a cryptography curve class."""
        matches = [m for m in cls if m.value.curve is curve]
        if not matches:
            err_msg = f'No NamedCurve with curve={curve!r}'
            raise ValueError(err_msg)
        if len(matches) > 1:
            err_msg = f'Multiple NamedCurve entries with curve={curve!r}'
            raise ValueError(err_msg)
        return matches[0]

    @classmethod
    def from_ossl_curve_name(cls, name: str) -> Self:
        """Return enum member matching an OpenSSL curve name."""
        for m in cls:
            if m.value.ossl_curve_name == name:
                return m
        err_msg = f'No NamedCurve with ossl_curve_name={name!r}'
        raise ValueError(err_msg)


class RsaPaddingScheme(enum.Enum):
    """RSA Padding Scheme Enum."""

    PKCS1v15 = 'PKCS#1 v1.5'
    PSS = 'PSS'


@dataclass(frozen=True)
class PublicKeyAlgorithmOidData:
    """The Public Key Algorithm OID Data class holding all of the information."""

    dotted_string: str | None
    verbose_name: str | None


class PublicKeyAlgorithmOid(enum.Enum):
    """Public Key Algorithm Enum holding algorithm OID metadata and lookup helpers."""

    NONE = PublicKeyAlgorithmOidData(None, None)
    ECC = PublicKeyAlgorithmOidData('1.2.840.10045.2.1', 'ECC')
    RSA = PublicKeyAlgorithmOidData('1.2.840.113549.1.1.1', 'RSA')

    @property
    def dotted_string(self) -> str | None:
        """Return the dotted string OID.

        Returns:
            The dotted string OID, or None.
        """
        return self.value.dotted_string

    @property
    def verbose_name(self) -> str | None:
        """Return the verbose name for display.

        Returns:
            The verbose name, or None.
        """
        return self.value.verbose_name

    @classmethod
    def from_dotted_string(cls, dotted_string: str | None) -> Self:
        """Return enum member matching a dotted_string."""
        for m in cls:
            if m.value.dotted_string == dotted_string:
                return m
        err_msg = f'No PublicKeyAlgorithmOid with dotted_string={dotted_string!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_verbose_name(cls, verbose_name: str | None) -> Self:
        """Return enum member matching a verbose_name."""
        for m in cls:
            if m.value.verbose_name == verbose_name:
                return m
        err_msg = f'No PublicKeyAlgorithmOid with verbose_name={verbose_name!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> PublicKeyAlgorithmOid:
        """Gets the PublicKeyAlgorithmOid enum matching the public key of the provided certificate.

        Args:
            certificate: The certificate to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.

        Raises:
            TypeError: If an unsupported key type contained in the certificate.
        """
        public_key = certificate.public_key
        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f'Unsupported key type contained in the certificate: {type(public_key)}.'
            raise TypeError(err_msg)

        return cls.from_public_key(public_key)

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeyAlgorithmOid:
        """Gets the PublicKeyAlgorithmOid enum matching the provided private key.

        Args:
            private_key: The private key to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.
        """
        return cls.from_public_key(private_key.public_key())

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> PublicKeyAlgorithmOid:
        """Gets the PublicKeyAlgorithmOid enum matching the provided public key.

        Args:
            public_key: The public_key to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return cls.RSA
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return cls.ECC
        err_msg = 'Unsupported key type, expected RSA or ECC key.'
        raise TypeError(err_msg)


@dataclass(frozen=True)
class HashAlgorithmData:
    """The Hash Algorithm OID Data class holding all of the information."""

    dotted_string: str
    verbose_name: str
    hash_algorithm: type[hashes.HashAlgorithm]


class HashAlgorithm(enum.Enum):
    """Hash Algorithm Enum holding OID metadata and lookup helpers."""

    MD5 = HashAlgorithmData('1.2.840.113549.2.5', 'MD5', hashes.MD5)
    SHA1 = HashAlgorithmData('1.3.14.3.2.26', 'SHA1', hashes.SHA1)
    SHA224 = HashAlgorithmData('2.16.840.1.101.3.4.2.4', 'SHA224', hashes.SHA224)
    SHA256 = HashAlgorithmData('2.16.840.1.101.3.4.2.1', 'SHA256', hashes.SHA256)
    SHA384 = HashAlgorithmData('2.16.840.1.101.3.4.2.2', 'SHA384', hashes.SHA384)
    SHA512 = HashAlgorithmData('2.16.840.1.101.3.4.2.3', 'SHA512', hashes.SHA512)

    # SHA-3 family
    SHA3_224 = HashAlgorithmData('2.16.840.1.101.3.4.2.7', 'SHA3-224', hashes.SHA3_224)
    SHA3_256 = HashAlgorithmData('2.16.840.1.101.3.4.2.8', 'SHA3-256', hashes.SHA3_256)
    SHA3_384 = HashAlgorithmData('2.16.840.1.101.3.4.2.9', 'SHA3-384', hashes.SHA3_384)
    SHA3_512 = HashAlgorithmData('2.16.840.1.101.3.4.2.10', 'SHA3-512', hashes.SHA3_512)

    # SHAKE algorithms
    SHAKE128 = HashAlgorithmData('2.16.840.1.101.3.4.2.11', 'Shake-128', hashes.SHAKE128)
    SHAKE256 = HashAlgorithmData('2.16.840.1.101.3.4.2.12', 'Shake-256', hashes.SHAKE256)

    @property
    def dotted_string(self) -> str:
        """Return the dotted string OID.

        Returns:
            The dotted string OID.
        """
        return self.value.dotted_string

    @property
    def verbose_name(self) -> str:
        """Return the verbose name for display.

        Returns:
            The verbose name.
        """
        return self.value.verbose_name

    @property
    def hash_algorithm(self) -> type[hashes.HashAlgorithm]:
        """Return the cryptography HashAlgorithm class.

        Returns:
            The HashAlgorithm class.
        """
        return self.value.hash_algorithm

    @classmethod
    def from_dotted_string(cls, dotted: str) -> Self:
        """Return enum member matching a dotted_string."""
        for m in cls:
            if m.value.dotted_string == dotted:
                return m
        err_msg = f'No HashAlgorithm with dotted_string={dotted!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_verbose_name(cls, verbose: str) -> Self:
        """Return enum member matching a verbose_name."""
        for m in cls:
            if m.value.verbose_name == verbose:
                return m
        err_msg = f'No HashAlgorithm with verbose_name={verbose!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_hash_algorithm_type(cls, algo_type: type[hashes.HashAlgorithm]) -> Self:
        """Return enum member matching a hashes.HashAlgorithm class."""
        for m in cls:
            if m.value.hash_algorithm is algo_type:
                return m
        err_msg = f'No HashAlgorithm with hash_algorithm={algo_type!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_hash_algorithm(cls, algo: hashes.HashAlgorithm) -> Self:
        """Return enum member matching a hashes.HashAlgorithm instance."""
        for m in cls:
            if isinstance(algo, m.value.hash_algorithm):
                return m
        err_msg = f'No HashAlgorithm with hash_algorithm={algo!r}'
        raise ValueError(err_msg)


@dataclass(frozen=True)
class AlgorithmIdentifierData:
    """The Algorithm Identifer Data class holding all of the information."""

    dotted_string: str
    verbose_name: str
    public_key_algo_oid: PublicKeyAlgorithmOid
    padding_scheme: RsaPaddingScheme | None
    hash_algorithm: HashAlgorithm | None


class AlgorithmIdentifier(enum.Enum):
    """Algorithm Identifier Enum holding combined algorithm metadata and lookup helpers."""

    RSA_MD5 = AlgorithmIdentifierData(
        '1.2.840.113549.1.1.4',
        'RSA with MD5',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.MD5,
    )
    RSA_SHA1 = AlgorithmIdentifierData(
        '1.2.840.113549.1.1.5',
        'RSA with SHA1',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA1,
    )
    RSA_SHA1_ALT = AlgorithmIdentifierData(
        '1.3.14.3.2.29',
        'RSA with SHA1',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA1,
    )
    RSA_SHA224 = AlgorithmIdentifierData(
        '1.2.840.113549.1.1.14',
        'RSA with SHA224',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA224,
    )
    RSA_SHA256 = AlgorithmIdentifierData(
        '1.2.840.113549.1.1.11',
        'RSA with SHA256',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA256,
    )
    RSA_SHA384 = AlgorithmIdentifierData(
        '1.2.840.113549.1.1.12',
        'RSA with SHA384',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA384,
    )
    RSA_SHA512 = AlgorithmIdentifierData(
        '1.2.840.113549.1.1.13',
        'RSA with SHA512',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA512,
    )
    RSA_SHA3_224 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.13',
        'RSA with SHA3-224',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_224,
    )
    RSA_SHA3_256 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.14',
        'RSA with SHA3-256',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_256,
    )
    RSA_SHA3_384 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.15',
        'RSA with SHA3-384',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_384,
    )
    RSA_SHA3_512 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.16',
        'RSA with SHA3-512',
        PublicKeyAlgorithmOid.RSA,
        RsaPaddingScheme.PKCS1v15,
        HashAlgorithm.SHA3_512,
    )

    # TODO(AlexHx8472): Add RSA PSS support. # noqa: FIX002, TD003

    ECDSA_SHA1 = AlgorithmIdentifierData(
        '1.2.840.10045.4.1',
        'ECDSA with SHA1',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA1,
    )
    ECDSA_SHA224 = AlgorithmIdentifierData(
        '1.2.840.10045.4.3.1',
        'ECDSA with SHA224',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA224,
    )
    ECDSA_SHA256 = AlgorithmIdentifierData(
        '1.2.840.10045.4.3.2',
        'ECDSA with SHA256',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA256,
    )
    ECDSA_SHA384 = AlgorithmIdentifierData(
        '1.2.840.10045.4.3.3',
        'ECDSA with SHA384',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA384,
    )
    ECDSA_SHA512 = AlgorithmIdentifierData(
        '1.2.840.10045.4.3.4',
        'ECDSA with SHA512',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA512,
    )
    ECDSA_SHA3_224 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.9',
        'ECDSA with SHA3-224',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA3_224,
    )
    ECDSA_SHA3_256 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.10',
        'ECDSA with SHA3-256',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA3_256,
    )
    ECDSA_SHA3_384 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.11',
        'ECDSA with SHA3-384',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA3_384,
    )
    ECDSA_SHA3_512 = AlgorithmIdentifierData(
        '2.16.840.1.101.3.4.3.12',
        'ECDSA with SHA3-512',
        PublicKeyAlgorithmOid.ECC,
        None,
        HashAlgorithm.SHA3_512,
    )
    PASSWORD_BASED_MAC = AlgorithmIdentifierData(
        '1.2.840.113533.7.66.13',
        'Password Based MAC',
        PublicKeyAlgorithmOid.NONE,
        None,
        None,
    )

    @property
    def dotted_string(self) -> str:
        """Return the dotted string OID.

        Returns:
            The dotted string OID.
        """
        return self.value.dotted_string

    @property
    def verbose_name(self) -> str:
        """Return the verbose name for display.

        Returns:
            The verbose name.
        """
        return self.value.verbose_name

    @property
    def public_key_algo_oid(self) -> PublicKeyAlgorithmOid:
        """Return the public key algorithm OID enum member.

        Returns:
            The PublicKeyAlgorithmOid member.
        """
        return self.value.public_key_algo_oid

    @property
    def padding_scheme(self) -> RsaPaddingScheme | None:
        """Return the RSA padding scheme.

        Returns:
            The RsaPaddingScheme member, or None.
        """
        return self.value.padding_scheme

    @property
    def hash_algorithm(self) -> HashAlgorithm | None:
        """Return the hash algorithm enum member.

        Returns:
            The HashAlgorithm member, or None.
        """
        return self.value.hash_algorithm

    @classmethod
    def from_dotted_string(cls, dotted: str) -> Self:
        """Return enum member matching a dotted_string."""
        for m in cls:
            if m.value.dotted_string == dotted:
                return m
        err_msg = f'No AlgorithmIdentifier with dotted_string={dotted!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_verbose_name(cls, verbose: str) -> Self:
        """Return enum member matching a verbose_name."""
        for m in cls:
            if m.value.verbose_name == verbose:
                return m
        err_msg = f'No AlgorithmIdentifier with verbose_name={verbose!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> AlgorithmIdentifier:
        """Gets the AlgorithmIdentifier enum matching the signature used to sign the certificate.

        Args:
            certificate: The certificate to get the PublicKeyAlgorithmOid for.

        Returns:
            The matching PublicKeyAlgorithmOid Enum.
        """
        for member in cls:
            if member.dotted_string == certificate.signature_algorithm_oid.dotted_string:
                return member
        err_msg = f'AlgorithmIdentifier {certificate.signature_algorithm_oid.dotted_string} is unkown.'
        raise ValueError(err_msg)


@dataclass(frozen=True)
class HmacAlgorithmData:
    """The HMAC Algorithm Data class holding all of the information."""

    dotted_string: str
    hash_algorithm: HashAlgorithm


class HmacAlgorithm(enum.Enum):
    """HMAC Algorithm Enum holding combined OID and hash algorithm metadata."""

    HMAC_MD5 = HmacAlgorithmData('1.3.6.1.5.5.8.1.1', HashAlgorithm.MD5)
    HMAC_SHA1 = HmacAlgorithmData('1.3.6.1.5.5.8.1.2', HashAlgorithm.SHA1)
    HMAC_SHA224 = HmacAlgorithmData('1.3.6.1.5.5.8.1.4', HashAlgorithm.SHA224)
    HMAC_SHA256 = HmacAlgorithmData('1.3.6.1.5.5.8.1.5', HashAlgorithm.SHA256)
    HMAC_SHA384 = HmacAlgorithmData('1.3.6.1.5.5.8.1.6', HashAlgorithm.SHA384)
    HMAC_SHA512 = HmacAlgorithmData('1.3.6.1.5.5.8.1.7', HashAlgorithm.SHA512)

    HMAC_SHA3_224 = HmacAlgorithmData('2.16.840.1.101.3.4.2.13', HashAlgorithm.SHA3_224)
    HMAC_SHA3_256 = HmacAlgorithmData('2.16.840.1.101.3.4.2.14', HashAlgorithm.SHA3_256)
    HMAC_SHA3_384 = HmacAlgorithmData('2.16.840.1.101.3.4.2.15', HashAlgorithm.SHA3_384)
    HMAC_SHA3_512 = HmacAlgorithmData('2.16.840.1.101.3.4.2.16', HashAlgorithm.SHA3_512)

    @property
    def dotted_string(self) -> str:
        """Return the dotted string OID.

        Returns:
            The dotted string OID.
        """
        return self.value.dotted_string

    @property
    def hash_algorithm(self) -> HashAlgorithm:
        """Return the HashAlgorithm enum member.

        Returns:
            The HashAlgorithm member.
        """
        return self.value.hash_algorithm

    @classmethod
    def from_dotted_string(cls, dotted: str) -> Self:
        """Return enum member matching a dotted_string."""
        for m in cls:
            if m.value.dotted_string == dotted:
                return m
        err_msg = f'No HmacAlgorithm with dotted_string={dotted!r}'
        raise ValueError(err_msg)

    @classmethod
    def from_hash_algorithm(cls, algo: HashAlgorithm) -> Self:
        """Return enum member matching a HashAlgorithm."""
        for m in cls:
            if m.value.hash_algorithm is algo:
                return m
        err_msg = f'No HmacAlgorithm with hash_algorithm={algo!r}'
        raise ValueError(err_msg)


class PublicKeyInfo:
    """Holds information and properties about a public key."""

    _public_key_algorithm_oid: PublicKeyAlgorithmOid
    _key_size: None | int = None
    _named_curve: None | NamedCurve = None

    def __init__(
        self,
        public_key_algorithm_oid: PublicKeyAlgorithmOid,
        key_size: None | int = None,
        named_curve: None | NamedCurve = None,
    ) -> None:
        """Initializes a PublicKeyInfo object.

        Args:
            public_key_algorithm_oid: The corresponding PublicKeyAlgorithmOid enum.
            key_size: The size of the key.
            named_curve: The NamedCurve enum, if it is an EC key.
        """
        self._public_key_algorithm_oid = public_key_algorithm_oid
        self._key_size = key_size
        if self._public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            if self._key_size is None:
                err_msg = 'Missing key size for RSA key.'
                raise ValueError(err_msg)
            if self._key_size < RSA_MIN_KEY_SIZE:
                err_msg = 'RSA key size must at least be 2048 bits.'
                raise ValueError(err_msg)
            if named_curve is not None:
                err_msg = 'RSA keys cannot have a named curve associated with it.'
                raise ValueError(err_msg)
        elif self._public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            if named_curve is None:
                err_msg = 'ECC key must have a named curve associated with it.'
                raise ValueError(err_msg)
            self._key_size = named_curve.key_size
            self._named_curve = named_curve

    def __eq__(self, other: object) -> bool:
        """Defines the behaviour on use of the equality operator.

        Args:
            other: The other PublicKeyInfo object to compare this instance to.

        Returns:
            True if the two objects are equal as defined by this method, False otherwise.
        """
        if not isinstance(other, PublicKeyInfo):
            return NotImplemented
        if self.public_key_algorithm_oid != other.public_key_algorithm_oid:
            return False
        if self.key_size != other.key_size:
            return False
        return self.named_curve == other.named_curve

    def __str__(self) -> str:
        """Constructs a human-readable string representation of this SignatureSuite.

        Returns:
            A human-readable string representation of this SignatureSuite.
        """
        if self.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            return f'RSA-{self.key_size}'
        if self.public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            if self.named_curve is None:
                err_msg = 'Failed to determine named curve.'
                raise ValueError(err_msg)
            return f'ECC-{self.named_curve.verbose_name}'
        return 'Invalid Signature Suite'

    @property
    def public_key_algorithm_oid(self) -> PublicKeyAlgorithmOid:
        """Property to get the associated PublicKeyAlgorithmOid.

        Returns:
            The associated PublicKeyAlgorithmOid.
        """
        return self._public_key_algorithm_oid

    @property
    def key_size(self) -> int | None:
        """Property to get the associated key size.

        Returns:
            The associated key size.
        """
        return self._key_size

    @property
    def named_curve(self) -> NamedCurve | None:
        """Property to get the associated NamedCurve.

        Returns:
            The associated NamedCurve.
        """
        return self._named_curve

    @classmethod
    def from_public_key(cls, public_key: PublicKey) -> PublicKeyInfo:
        """Gets the corresponding PublicKeyInfo for the public key.

        Args:
            public_key: The public key to get the corresponding PublicKeyInfo for.

        Returns:
            The corresponding PublicKeyInfo for the public key.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return cls(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.RSA,
                key_size=public_key.key_size,
            )
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return cls(
                public_key_algorithm_oid=PublicKeyAlgorithmOid.ECC,
                key_size=public_key.key_size,
                named_curve=NamedCurve[public_key.curve.name.upper()],
            )
        err_msg = 'Unsupported public key type found. Must be RSA or ECC key.'
        raise TypeError(err_msg)

    @classmethod
    def from_private_key(cls, private_key: PrivateKey) -> PublicKeyInfo:
        """Gets the corresponding PublicKeyInfo for the private key.

        Args:
            private_key: The private key to get the corresponding PublicKeyInfo for.

        Returns:
            The corresponding PublicKeyInfo for the private key.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        return cls.from_public_key(private_key.public_key())

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> PublicKeyInfo:
        """Gets the corresponding PublicKeyInfo for the certificate.

        Args:
            certificate: The certificate to get the corresponding PublicKeyInfo for.

        Returns:
            The corresponding PublicKeyInfo for the certificate.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        public_key = certificate.public_key()
        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f'Unsupported key type contained in the certificate: {type(public_key)}.'
            raise TypeError(err_msg)

        return cls.from_public_key(public_key)


class SignatureSuite:
    """Holds information and properties about a signature suite."""

    _public_key_info: PublicKeyInfo
    _algorithm_identifier: AlgorithmIdentifier

    def __init__(self, algorithm_identifier: AlgorithmIdentifier, public_key_info: PublicKeyInfo) -> None:
        """Initializes a SignatureSuite object.

        Args:
            algorithm_identifier: The corresponding AlgorithmIdentifier enum.
            public_key_info: The corresponding PublicKeyInfo enum.
        """
        self._algorithm_identifier = algorithm_identifier
        self._public_key_info = public_key_info

        self._validate_consistency()

    def __eq__(self, other: object) -> bool:
        """Defines the behaviour on use of the equality operator.

        Args:
            other: The other SignatureSuite object to compare this instance to.

        Returns:
            True if the two objects are equal as defined by this method, False otherwise.
        """
        if not isinstance(other, SignatureSuite):
            return NotImplemented

        return self.public_key_info == other.public_key_info and self.algorithm_identifier == other.algorithm_identifier

    def __str__(self) -> str:
        """Constructs a human-readable string representation of this SignatureSuite.

        Returns:
            A human-readable string representation of this SignatureSuite.
        """
        if self.algorithm_identifier.hash_algorithm is None:
            err_msg = 'Failed to determine hash algorithm.'
            raise ValueError(err_msg)
        hash_alg_name = self.algorithm_identifier.hash_algorithm.verbose_name
        if self.public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            return f'RSA-{self.public_key_info.key_size}-{hash_alg_name}'
        if self.public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            if self.public_key_info.named_curve is None:
                err_msg = 'Named curve not found.'
                raise ValueError(err_msg)
            return f'ECC-{self.public_key_info.named_curve.verbose_name}-{hash_alg_name}'
        return 'Invalid Signature Suite'

    def _validate_consistency(self) -> None:
        """Validates if the PublicKeyInfo details matches the AlgorithmIdentifier.

        This makes sure that the private key matches the algorithm used to sign a certificate. We are not supporting
        different signature suites within the same domain (PKI hierarchy).

        Raises:
            ValueError: If the consistency check failed.
        """
        if self.algorithm_identifier.public_key_algo_oid != self.public_key_info.public_key_algorithm_oid:
            err_msg = (
                f'Signature algorithm uses {self.algorithm_identifier.public_key_algo_oid.name}, '
                f'but the public key is a {self.public_key_info.public_key_algorithm_oid.name} key.'
            )
            raise ValueError(err_msg)

    @property
    def algorithm_identifier(self) -> AlgorithmIdentifier:
        """Property to get the associated AlgorithmIdentifier.

        Returns:
            The associated AlgorithmIdentifier.
        """
        return self._algorithm_identifier

    @property
    def public_key_info(self) -> PublicKeyInfo:
        """Property to get the associated PublicKeyInfo.

        Returns:
            The associated PublicKeyInfo.
        """
        return self._public_key_info

    @classmethod
    def from_certificate(cls, certificate: x509.Certificate) -> SignatureSuite:
        """Gets the corresponding SignatureSuite for the certificate.

        Args:
            certificate: The certificate to get the corresponding SignatureSuite for.

        Returns:
            The corresponding SignatureSuite for the certificate.

        Raises:
            ValueError:
                If the public key contained in the certificate does not match the
                signature suite used to sign the certificate.

            TypeError: If the key provided is of a type that is not supported.
        """
        return cls(
            algorithm_identifier=AlgorithmIdentifier.from_certificate(certificate),
            public_key_info=PublicKeyInfo.from_certificate(certificate),
        )

    def public_key_matches_signature_suite(self, public_key: PublicKey) -> bool:
        """Checks if the provided public key can be used with this SignatureSuite.

        Args:
            public_key: The public key to check against this SignatureSuite.

        Returns:
            True if the public key can be used with this SignatureSuite, False otherwise.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        public_key_info = PublicKeyInfo.from_public_key(public_key)
        return self.public_key_info == public_key_info

    def private_key_matches_signature_suite(self, private_key: PrivateKey) -> bool:
        """Checks if the provided private key can be used with this SignatureSuite.

        Args:
            private_key: The private key to check against this SignatureSuite.

        Returns:
            True if the private key can be used with this SignatureSuite, False otherwise.

        Raises:
            TypeError: If the key provided is of a type that is not supported.
        """
        return self.public_key_matches_signature_suite(private_key.public_key())

    def certificate_matches_signature_suite(self, certificate: x509.Certificate) -> bool:
        """Checks if the provided certificate can be used with this SignatureSuite.

        Args:
            certificate: The certificate to check against this SignatureSuite.

        Returns:
            True if the certificate can be used with this SignatureSuite, False otherwise.

        Raises:
            ValueError:
                If the public key contained in the certificate does not match the
                signature suite used to sign the certificate.

            TypeError: If the key provided is of a type that is not supported.
        """
        signature_suite = SignatureSuite.from_certificate(certificate)
        return self == signature_suite


class KeyPairGenerator:
    """Helper methods to generate key pairs corresponding to several objects."""

    @staticmethod
    def generate_key_pair_for_public_key(public_key: PublicKey) -> PrivateKey:
        """Generates a new key-pair with the same type and key size as the provided public key.

        Args:
            public_key: The public key used to determine the key type and key size to generate the new key-pair.

        Returns:
            The generated key pair.

        Raises:
            TypeError: If the key type of the provided public key is not supported.
        """
        if isinstance(public_key, rsa.RSAPublicKey):
            return rsa.generate_private_key(public_exponent=65537, key_size=public_key.key_size)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return ec.generate_private_key(public_key.curve)
        err_msg = 'Unsupported key type found.'
        raise TypeError(err_msg)

    @classmethod
    def generate_key_pair_for_private_key(cls, private_key: PrivateKey) -> PrivateKey:
        """Generates a new key-pair with the same type and key size as the provided private key.

        Args:
            private_key: The private key used to determine the key type and key size to generate the new key-pair.

        Returns:
            The generated key-pair.

        Raises:
            TypeError: If the key type of the provided private key is not supported.
        """
        return cls.generate_key_pair_for_public_key(private_key.public_key())

    @classmethod
    def generate_key_pair_for_certificate(cls, certificate: x509.Certificate) -> PrivateKey:
        """Generates a new key-pair with the same type and key size as the public key present in the certificate.

        Args:
            certificate: The certificate used to determine the key type and key size to generate the new key-pair.

        Returns:
            The generated key-pair.

        Raises:
            TypeError: If the key type of the provided public key within the certificate is not supported.
        """
        public_key = certificate.public_key()
        if not isinstance(public_key, typing.get_args(PublicKey)):
            err_msg = f'Unsupported key type contained in the certificate: {type(public_key)}.'
            raise TypeError(err_msg)

        return cls.generate_key_pair_for_public_key(public_key)

    @staticmethod
    def generate_key_pair_for_public_key_info(
        public_key_info: PublicKeyInfo,
    ) -> PrivateKey:
        """Generates a new key-pair of the type given by the PublicKeyInfo object.

        Args:
            public_key_info: The PublicKeyInfo object determining the key type of the key-pair to generate.

        Returns:
            The generated key-pair.

        Raises:
            ValueError: If the RSA key size is too small or no named curve is given when generating an EC key.
            TypeError: If the key type of the provided PublicKeyInfo is not supported.
        """
        if public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.RSA:
            if public_key_info.key_size is None:
                err_msg = 'Failed to determine key size.'
                raise ValueError(err_msg)
            if public_key_info.key_size < RSA_MIN_KEY_SIZE:
                err_msg = (
                    f'RSA key size must be at least {RSA_MIN_KEY_SIZE} bits, but found {public_key_info.key_size} bits.'
                )
                raise ValueError(err_msg)
            if public_key_info.key_size is None:
                err_msg = 'Failed to determine key size.'
                raise ValueError(err_msg)
            return rsa.generate_private_key(public_exponent=65537, key_size=public_key_info.key_size)
        if public_key_info.public_key_algorithm_oid == PublicKeyAlgorithmOid.ECC:
            if public_key_info.named_curve is None:
                err_msg = 'Named curve missing. Only named curves are supported for ECC keys.'
                raise ValueError(err_msg)
            if public_key_info.named_curve is None or public_key_info.named_curve.curve is None:
                err_msg = 'Curve not found.'
                raise ValueError(err_msg)
            return ec.generate_private_key(curve=public_key_info.named_curve.curve())
        err_msg = 'Unsupported key type found.'
        raise TypeError(err_msg)

    @classmethod
    def generate_key_pair_for_signature_suite(cls, signature_suite: SignatureSuite) -> PrivateKey:
        """Generates a new key-pair of the type given by the SignatureSuite object.

        Args:
            signature_suite: The SignatureSuite object determining the key type of the key-pair to generate.

        Returns:
            The generated key-pair.

        Raises:
            ValueError: If the RSA key size is too small or no named curve is given when generating an EC key.
            TypeError: If the key type of the provided PublicKeyInfo is not supported.
        """
        return cls.generate_key_pair_for_public_key_info(signature_suite.public_key_info)
