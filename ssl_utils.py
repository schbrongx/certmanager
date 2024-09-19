from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import OpenSSL
import datetime

def validate_certificate(cert_path, key_path):
    # Load the certificate
    try:
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)

        # Load the private key
        with open(key_path, 'rb') as key_file:
            key_data = key_file.read()
            private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_data)

        # Validate that the key matches the certificate
        context = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_METHOD)
        context.use_privatekey(private_key)
        context.use_certificate(cert)
        context.check_privatekey()
        
        return True
    except Exception as e:
        print(f"Error validating certificate: {e}")
        return False

def get_certificate_expiration(cert_path):
    try:
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        
        expiration_date = cert.not_valid_after
        return expiration_date.strftime('%Y-%m-%d')
    except Exception as e:
        print(f"Error extracting expiration date: {e}")
        return None

def extract_certificate_info(cert_path):
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Extract version
        version = cert.version.name

        # Extract issuer details
        issuer = {
            'CN': cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) else None,
            'O': cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None,
            'OU': cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME) else None,
            'C': cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value if cert.issuer.get_attributes_for_oid(NameOID.COUNTRY_NAME) else None,
        }

        # Extract subject details
        subject = {
            'CN': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) else None,
            'O': cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else None,
            'OU': cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME) else None,
            'L': cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.LOCALITY_NAME) else None,
            'S': cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.STATE_OR_PROVINCE_NAME) else None,
            'C': cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value if cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME) else None,
        }

        # Extract validity period
        valid_from = cert.not_valid_before
        valid_to = cert.not_valid_after

        # Extract public key information
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            pubkey_algorithm = "RSA"
            pubkey_length = public_key.key_size
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            pubkey_algorithm = "Elliptic Curve"
            pubkey_length = public_key.key_size
        else:
            pubkey_algorithm = "Unknown"
            pubkey_length = None

        # Extract Subject Alternative Names (SAN) if present
        try:
            san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = None

        # Extract Basic Constraints if present
        try:
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = basic_constraints.ca
        except x509.ExtensionNotFound:
            is_ca = None

        # Extract Key Usage if present
        try:
            key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            usage = {
                'digital_signature': key_usage.digital_signature,
                'key_encipherment': key_usage.key_encipherment,
                'key_cert_sign': key_usage.key_cert_sign,
                'crl_sign': key_usage.crl_sign,
            }
        except x509.ExtensionNotFound:
            usage = None

        # Return the extracted information as a dictionary
        return {
            'version': version,
            'issuer': issuer,
            'subject': subject,
            'valid_from': valid_from,
            'valid_to': valid_to,
            'public_key_algorithm': pubkey_algorithm,
            'public_key_length': pubkey_length,
            'san': san,
            'is_ca': is_ca,
            'key_usage': usage
        }

