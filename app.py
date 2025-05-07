from flask import Flask, render_template, request, redirect, url_for, send_file
import os
import json
import uuid
import base64
from dotenv import load_dotenv
from datetime import datetime, timedelta
from io import BytesIO
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Folder where secrets are stored
SECRETS_FOLDER = 'secrets'
os.makedirs(SECRETS_FOLDER, exist_ok=True)

# Set expiration time for secrets (e.g., 2 minutes)
EXPIRATION_TIME = timedelta(minutes=2)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Save the private key to a file
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save the public key to a file
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_secret', methods=['POST'])
def create_secret():
    public_key_pem = request.form.get('public_key')
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
    elif text_secret:
        secret_content = text_secret

    # Encrypt the secret content with the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    encrypted_content = public_key.encrypt(
        secret_content.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    secret_id = str(uuid.uuid4())
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")
    created_at = datetime.utcnow()
    expires_at = created_at + EXPIRATION_TIME

    with open(filepath, 'w') as f:
        json.dump({
            "secret": base64.b64encode(encrypted_content).decode(),
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "is_file": is_file,
            "filename": filename,
            "mimetype": mimetype
        }, f)

    share_url = url_for('secret', secret_id=secret_id, _external=True)
    return render_template('share.html', url=share_url)

@app.route('/secret/<secret_id>', methods=['GET'])
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

    # Do not decrypt on server, send encrypted payload to client for RSA decryption
    time_remaining = expires_at - datetime.utcnow()

    return render_template(
        "confirm.html",
        secret_id=secret_id,
        encrypted=data['secret'],
        is_file=data['is_file'],
        filename=data['filename'],
        mimetype=data['mimetype'],
        time_remaining=time_remaining
    )

@app.route('/download_file', methods=['POST'])
def download_file():
    file_data = base64.b64decode(request.form['file_data'])
    filename = request.form['filename']
    mimetype = request.form['mimetype']
    return send_file(
        BytesIO(file_data),
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port, debug=True)
