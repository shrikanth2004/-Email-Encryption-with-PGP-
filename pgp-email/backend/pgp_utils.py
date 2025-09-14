# backend/pgp_utils.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64, json, os

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")

def encrypt_message(message: str) -> str:
    # Load recipient public key
    with open(os.path.join(KEYS_DIR, "public_key.pem"), "rb") as f:
        public_key = RSA.import_key(f.read())

    # Generate random AES session key
    session_key = get_random_bytes(16)

    # Encrypt session key with RSA public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt message with AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode("utf-8"))

    # Return JSON encoded base64
    return json.dumps({
        "enc_session_key": base64.b64encode(enc_session_key).decode("utf-8"),
        "nonce": base64.b64encode(cipher_aes.nonce).decode("utf-8"),
        "tag": base64.b64encode(tag).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    })

def decrypt_message(encrypted_json: str) -> str:
    with open(os.path.join(KEYS_DIR, "private_key.pem"), "rb") as f:
        private_key = RSA.import_key(f.read())

    b64 = json.loads(encrypted_json)

    enc_session_key = base64.b64decode(b64["enc_session_key"])
    nonce = base64.b64decode(b64["nonce"])
    tag = base64.b64decode(b64["tag"])
    ciphertext = base64.b64decode(b64["ciphertext"])

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    message = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return message.decode("utf-8")
