from flask import Flask, send_from_directory

app = Flask(__name__, static_folder="../frontend/static")

@app.route("/")
def serve_index():
    return send_from_directory("../frontend", "index.html")

# serve CSS/JS files properly
@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory("../frontend/static", filename)

if __name__ == "__main__":
    app.run(debug=True)
