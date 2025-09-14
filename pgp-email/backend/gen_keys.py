# backend/gen_keys.py
from Crypto.PublicKey import RSA

key = RSA.generate(2048)

private_key = key.export_key()
with open("keys/private_key.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("keys/public_key.pem", "wb") as f:
    f.write(public_key)

print("✅ RSA Keys generated in /keys folder")
