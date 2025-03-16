
"""
Le processus de génération d'une paire de clés RSA, chiffrant un message avec la clé publique,
puis le déchiffrer avec la clé privée correspondante.
Ce schéma améliore la sécurité du cryptage RSA.
"""
#Install the cryptography libraries !pip install cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048)

print(f"\n Private key: {private_key}")

# Generate public key
public_key = private_key.public_key()

print( "\n Public key:", public_key)


# Message to be encrypted
message = b"Confidential information! NSA - we are ready to advance the mission!"


# encrypt the message
cipher_text = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))

print(" \n Cipher Text:", cipher_text)

# decrypt the message
plain_text = private_key.decrypt(
    cipher_text,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    ))


# decode the plain text
print(" \n Decrypted Text:", plain_text.decode())


    

