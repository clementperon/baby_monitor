import base64
import json
from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys

def aes_ctr_encrypt(input_file, output_file, key_hex, iv_hex):
    try:
        # Convert hex key and IV to bytes
        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)

        # Validate key and IV lengths
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (64 hex characters).")
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes (32 hex characters).")

        # Read the JSON data
        with open(input_file, 'r') as file:
            json_data = json.load(file)

        # Convert the JSON data to a string and escape quotes
        json_string = json.dumps(json_data)
        print(json_string)
        escaped_json_string = json_string.replace('"', '\\"')

        # Initialize AES-CTR with the IV as the counter's initial value
        counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

        # Encrypt the escaped JSON string
        encrypted_data = cipher.encrypt(escaped_json_string.encode('utf-8'))

        # Combine key, IV, and encrypted data
        combined_data = key + iv + encrypted_data

        # Encode the combined data in Base64
        base64_encoded = base64.b64encode(combined_data).decode('utf-8')

        # Write the Base64-encoded data to the output file
        with open(output_file, 'w') as output:
            output.write(base64_encoded)

        print(f"Encryption successful! The Base64-encoded encrypted data has been saved to {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python encrypt_aesctr.py <input_json_file> <output_file> <key_hex> <iv_hex>")
    else:
        aes_ctr_encrypt(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
