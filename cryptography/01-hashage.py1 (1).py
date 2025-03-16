from Crypto.Hash import SHA256


data = b"MDP - ECAM_EPMI_Cyber@2024!"

hash_object = SHA256.new(data)

hashed_data = hash_object.digest()

print(f"\n Original Data: {data}")
print(f"\n SHA-256 Hash in Bytes: {hashed_data}")
print(f"\n SHA-256 Hash (hex): {hashed_data.hex()}")