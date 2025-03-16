
"""
Cryptage et déchiffrement AES (Advanced Encryption Standard) en mode CBC (Cipher Block Chaining).
Le code génère une clé aléatoire de 128 bits (16 octets), chiffre les données à l'aide du chiffrement AES, puis
le décrypte jusqu'aux données d'origine.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Generate a random 128-bit key for AES encryption
key = get_random_bytes(16)

# Data to be encrypted
data = b"Secret text: Advanced Encryption Standard ou AES"

# AES encryption using Cipher Block Chaining (CBC) mode
cipher = AES.new(key, AES.MODE_CBC)
ciphertext = cipher.encrypt(pad(data, AES.block_size))

# AES decryption using the same key and initialization vector (iv) from the encryption
decipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
decrypted_data = unpad(decipher.decrypt(ciphertext), AES.block_size)

# Display the original, encrypted, and decrypted data
print(f" \n Original Data: {data}")
print(f" \n Encrypted Data: {ciphertext}")
print(f" \n Decrypted Data: {decrypted_data.decode('utf-8')}")
