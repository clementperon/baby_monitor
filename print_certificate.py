from cryptography import x509
from cryptography.hazmat.primitives import hashes
import ssl
import base64
import sys
import os


def fetch_tls_certificate_info_from_hostname(hostname, port=443):
    """
    Fetches TLS certificate information from a given hostname.

    Args:
        hostname (str): The domain name to fetch the certificate from.
        port (int): The port to connect to (default is 443).

    Returns:
        dict: A dictionary containing sha256 fingerprint, ver, and eTime.
    """
    try:
        # Fetch the server certificate
        pem_data = ssl.get_server_certificate((hostname, port))

        # Load the certificate using cryptography
        cert_data = x509.load_pem_x509_certificate(pem_data.encode())

        return extract_certificate_info(cert_data)

    except Exception as e:
        print(f"Error fetching TLS certificate from hostname: {e}")
        return None


def fetch_tls_certificate_info_from_file(file_path):
    """
    Fetches TLS certificate information from a PEM or CER file.

    Args:
        file_path (str): Path to the PEM or CER file.

    Returns:
        dict: A dictionary containing sha256 fingerprint, ver, and eTime.
    """
    try:
        # Read the certificate file
        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Detect if the file is PEM-encoded or DER-encoded
        if b"-----BEGIN CERTIFICATE-----" in file_data:
            # PEM format
            cert_data = x509.load_pem_x509_certificate(file_data)
        else:
            # DER format
            cert_data = x509.load_der_x509_certificate(file_data)

        return extract_certificate_info(cert_data)

    except Exception as e:
        print(f"Error reading certificate file: {e}")
        return None


def extract_certificate_info(cert_data):
    """
    Extracts SHA256 fingerprint, version, and expiration time from a certificate.

    Args:
        cert_data (x509.Certificate): The loaded certificate object.

    Returns:
        dict: A dictionary containing sha256 fingerprint, ver, and eTime.
    """
    try:
        # Compute SHA256 hash of the certificate in DER format
        sha256_fingerprint_binary = cert_data.fingerprint(hashes.SHA256())  # Binary representation
        sha256_hex = sha256_fingerprint_binary.hex()

        # Create a ver field using the base64-encoded fingerprint
        ver_binary = base64.b64encode(sha256_fingerprint_binary).decode()
        ver = f"sha256/{ver_binary}"

        # Extract the expiration date in UTC
        expiry_date_utc = cert_data.not_valid_after_utc
        eTime = int(expiry_date_utc.timestamp())

        return {"sha256": sha256_hex, "ver": ver, "eTime": eTime}

    except Exception as e:
        print(f"Error extracting certificate info: {e}")
        return None


def is_file_path(input_value):
    """
    Checks if the input value is a valid file path.

    Args:
        input_value (str): The input string to check.

    Returns:
        bool: True if it's a valid file path, False otherwise.
    """
    return os.path.isfile(input_value)


if __name__ == "__main__":
    # Check if the input value was provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python script.py <hostname_or_file_path>")
        sys.exit(1)

    input_value = sys.argv[1]

    # Determine whether the input is a file path or a hostname
    if is_file_path(input_value):
        # Process as a file path
        cert_info = fetch_tls_certificate_info_from_file(input_value)
    else:
        # Process as a hostname
        cert_info = fetch_tls_certificate_info_from_hostname(input_value)

    if cert_info:
        print("TLS Certificate Information:")
        print(f"  SHA256: {cert_info['sha256']}")
        print(f"  Ver: {cert_info['ver']}")
        print(f"  Expiration Time (eTime): {cert_info['eTime']}")
    else:
        print("Failed to retrieve certificate information.")
