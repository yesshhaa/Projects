# test_server.py
from flask import Flask
app = Flask(__name__)

@app.route("/admin")
def admin():
    return "Admin panel", 200

@app.route("/private")
def private():
    return "Forbidden", 403

if __name__ == "__main__":
    app.run(port=8000)
    