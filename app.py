from flask import Flask, render_template, request, redirect, url_for
import os
import json
import uuid
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
app = Flask(__name__)

SECRETS_FOLDER = 'secrets'
os.makedirs(SECRETS_FOLDER, exist_ok=True)

FERNET_KEY = os.getenv('FERNET_KEY')
if not FERNET_KEY:
    raise ValueError("FERNET_KEY missing in environment.")
fernet = Fernet(FERNET_KEY)

EXPIRATION_TIME = timedelta(minutes=2)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_secret', methods=['POST'])
def create_secret():
    password = request.form.get('password')
    text_secret = request.form.get('secret')
    uploaded_file = request.files.get('file')

    if not text_secret and not uploaded_file:
        return "Provide a secret or upload a file.", 400

    is_file = False
    secret_content = ""
    filename = ""
    mimetype = ""

    if uploaded_file and uploaded_file.filename:
        file_bytes = uploaded_file.read()
        base64_file = base64.b64encode(file_bytes).decode()
        secret_content = base64_file
        filename = uploaded_file.filename
        mimetype = uploaded_file.mimetype
        is_file = True
    else:
        secret_content = text_secret

    encrypted = fernet.encrypt(secret_content.encode()).decode()
    secret_id = str(uuid.uuid4())
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")
    created_at = datetime.utcnow()
    expires_at = created_at + EXPIRATION_TIME
    password_hash = generate_password_hash(password) if password else None

    with open(filepath, 'w') as f:
        json.dump({
            "secret": encrypted,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "password_hash": password_hash,
            "is_file": is_file,
            "filename": filename,
            "mimetype": mimetype
        }, f)

    share_url = url_for('secret', secret_id=secret_id, _external=True)
    return render_template('share.html', url=share_url)

@app.route('/secret/<secret_id>', methods=['GET', 'POST'])
def secret(secret_id):
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")
    if not os.path.exists(filepath):
        return render_template("expired.html")

    with open(filepath, 'r') as f:
        data = json.load(f)

    expires_at = datetime.fromisoformat(data['expires_at'])
    if datetime.utcnow() > expires_at:
        os.remove(filepath)
        return render_template("expired.html")

    if request.method == 'POST':
        password = request.form.get('password')
        if data['password_hash'] and not check_password_hash(data['password_hash'], password):
            return "Invalid password.", 403

        decrypted = fernet.decrypt(data['secret'].encode()).decode()
        os.remove(filepath)

        if data.get("is_file"):
            return render_template("secret.html", secret=decrypted, is_file=True, filename=data["filename"])
        else:
            return render_template("secret.html", secret=decrypted, is_file=False)

    time_remaining = expires_at - datetime.utcnow()
    return render_template("confirm.html", secret_id=secret_id, time_remaining=time_remaining, password_required=data['password_hash'])

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
