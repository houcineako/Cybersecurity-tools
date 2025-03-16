
"""
Ce code démontre l'utilisation du HMAC (Hash-based Message Authentication Code) pour authentifier les données.
Les fonctions de hachage, y compris HMAC (Hash-based Message Authentication Code), sont conçues pour être des
fonctions unidirectionnelles.Cela signifie que le processus de hachage est irréversible et que vous ne 
pouvez pas récupérer directement les données originales à partir de la valeur de hachage.
"""


from Crypto.Hash import HMAC, SHA256

# Secret key for HMAC
key = b"secret_key_login"

# Data to be authenticated
data = b"MDP - ECAM_EPMI_Cyber@2024!"

# Generate HMAC using the SHA-256 hash function and the secret key
hmac = HMAC.new(key, msg=data, digestmod=SHA256)

# Display the original data and the generated HMAC
print(f" \n Original Data: {data}")
print(f" \n Hmac in Bytes: {hmac.digest()}")
print(f" \n HMAC: {hmac.hexdigest()}")
