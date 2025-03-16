"""
Ce code illustre le processus de base de génération et de vérification de signatures numériques
à l'aide d'une paire de clés RSA. Il peut être utilisé dans des scénarios où l'intégrité et
l'authenticité des données sont cruciales, telles que la communication sécurisée ou
l'authentification des messages.
"""

#Install the cryptography libraries !pip install cryptography

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
# Message to be signed

message = b"Highly important message to be signed! - NSA"

# Create a signature - sign
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),algorithm=hashes.SHA256())


print(" \n Signature:", signature)

# verify the signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ), algorithm=hashes.SHA256())
    
    print("\n Signature is valid.")
    
except Key as e:
    print("\n Signature is not valid.")