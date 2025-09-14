from flask import Flask, request, jsonify, send_from_directory
from pgp_utils import encrypt_message, decrypt_message

app = Flask(__name__, static_folder="../frontend/static")

@app.route("/")
def serve_index():
    return send_from_directory("../frontend", "index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    msg = data.get("message", "")
    encrypted = encrypt_message(msg)
    return jsonify({"encrypted": encrypted})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.get_json()
    encrypted = data.get("encrypted", "")
    decrypted = decrypt_message(encrypted)
    return jsonify({"decrypted": decrypted})

# serve CSS/JS files
@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory("../frontend/static", filename)

if __name__ == "__main__":
    app.run(debug=True)
