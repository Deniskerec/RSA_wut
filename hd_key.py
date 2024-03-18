#Hierarchical Deterministic (HD) Keys
# typically use elliptic curve cryptography (ECC)

#RSA doesn't support HD key generation in the way ECC does

#"master" RSA key and an input number.

import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_rsa_private_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def generate_seed_from_rsa_and_input(rsa_private_key, input_number):
    # Serialize the RSA private key
    pem_private = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Hash keyO + input number
    hasher = hashlib.sha256()
    hasher.update(pem_private)
    hasher.update(str(input_number).encode())
    return hasher.digest()

def main():
    # 
    rsa_key_file_name = input(".pem name ")
    
    try:
        parent_private_key = load_rsa_private_key_from_file(rsa_key_file_name)
    
        input_number = int(input("Enter a number: "))
    
        # Generate a seed
        seed = generate_seed_from_rsa_and_input(parent_private_key, input_number)
        print(f"(SHA-256 hash): {seed.hex()}")
    except FileNotFoundError:
        print(f"No file dumb fuck {rsa_key_file_name}")
    except Exception as e:
        print(f"Error {e}")

if __name__ == "__main__":
    main()


#Loading the RSA Key: The script starts by loading your existing RSA private key from a file.
#Asking for a Number
#SHA-256 algorithm to mix them together 
    
# unique SHA-256 based on RSA private key + numeric input
    # use the seed for ? no clue 
    # simon halp ! 