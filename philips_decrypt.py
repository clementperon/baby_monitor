import base64
import json
from Crypto.Cipher import AES
from Crypto.Util import Counter
import sys

def aes_ctr_decrypt(file_path):
    try:
        # Read the file
        with open(file_path, 'r') as file:
            base64_data = file.read().strip()

        # Decode the Base64 content
        decoded_data = base64.b64decode(base64_data)

        # Extract the first 32 bytes as the AES key
        key = decoded_data[:32]
        iv = decoded_data[32:48]  # Next 16 bytes
        encrypted_data = decoded_data[48:]

        print(f"Key used: {key.hex()}")
        print(f"IV used: {iv.hex()}")

        # Initialize AES-CTR with a counter
        counter = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

        # Decrypt the encrypted data
        decrypted_data = cipher.decrypt(encrypted_data)

        # Parse the decrypted data as JSON
        try:
            decoded_json_string = decrypted_data.decode('utf-8').replace('\\"', '"')
            json_data = json.loads(decoded_json_string)
            print("Decrypted JSON Data:")
            print(json.dumps(json_data, indent=4))  # Pretty print the JSON
        except json.JSONDecodeError:
            print("Decrypted data is not valid JSON:")
            print(decrypted_data.decode('utf-8', errors='ignore'))

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python decrypt_aesctr.py <file_path>")
    else:
        aes_ctr_decrypt(sys.argv[1])
