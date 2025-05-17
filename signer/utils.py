import hashlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
from cryptography.hazmat.primitives.serialization import pkcs12


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hashlib.sha256(password.encode()).hexdigest() == hashed

def generate_self_signed_cert(name, email, password):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        # x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
        # x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        # x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        # x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT Department"),
        # x509.NameAttribute(NameOID.STREET_ADDRESS, "1234 Main St"),
        # x509.NameAttribute(NameOID.POSTAL_CODE, "94105"),
        # x509.NameAttribute(NameOID.DISTINGUISHED_NAME_QUALIFIER, "My Company"),
        # x509.NameAttribute(NameOID.TITLE, "Software Engineer"),
        # x509.NameAttribute(NameOID.GIVEN_NAME, name),
        # x509.NameAttribute(NameOID.SURNAME, "Doe"),
        # x509.NameAttribute(NameOID.PSEUDONYM, "jdoe"),
        # x509.NameAttribute(NameOID.DN_QUALIFIER, "My DN Qualifier"),
        # x509.NameAttribute(NameOID.DOMAIN_COMPONENT, "example.com"),
        # x509.NameAttribute(NameOID.USER_ID, "
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )

    # Serialize into .p12 (PKCS12)
    p12_bytes = pkcs12.serialize_key_and_certificates(
        name.encode(),
        key,
        cert,
        None,
        serialization.BestAvailableEncryption(password.encode())
    )

    return p12_bytes
