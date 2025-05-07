from flask import Flask, render_template, request, redirect, url_for, send_file
import os
import json
import uuid
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO



# Load environment variables
load_dotenv()

app = Flask(__name__)

# Folder where secrets are stored
SECRETS_FOLDER = 'secrets'
os.makedirs(SECRETS_FOLDER, exist_ok=True)

# Load the encryption key from the environment variable
FERNET_KEY = os.getenv('FERNET_KEY')
if not FERNET_KEY:
    raise ValueError("FERNET_KEY missing in environment.")
fernet = Fernet(FERNET_KEY)

# Set expiration time for secrets (e.g., 2 minutes)
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

    # Encrypt the secret (text or file content)
    encrypted = fernet.encrypt(secret_content.encode()).decode()
    secret_id = str(uuid.uuid4())
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")
    created_at = datetime.utcnow()
    expires_at = created_at + EXPIRATION_TIME
    password_hash = generate_password_hash(password) if password else None

    # Save the encrypted secret and metadata to a JSON file
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

    # Generate the shareable link for the secret
    share_url = url_for('secret', secret_id=secret_id, _external=True)
    
    # Return the URL to the user to share immediately
    return render_template('share.html', url=share_url)

@app.route('/secret/<secret_id>', methods=['GET', 'POST'])
def secret(secret_id):
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")

    # Check if the secret file exists
    if not os.path.exists(filepath):
        return render_template("expired.html")

    # Load secret data from the file
    with open(filepath, 'r') as f:
        data = json.load(f)

    expires_at = datetime.fromisoformat(data['expires_at'])

    # Check if the secret has expired
    if datetime.utcnow() > expires_at:
        os.remove(filepath)
        return render_template("expired.html")

    if request.method == 'POST':
        password = request.form.get('password')

        # Check if a password is required and if the user provided one
        if data['password_hash'] and not check_password_hash(data['password_hash'], password):
            return "Invalid password.", 403

        # Decrypt the secret
        decrypted = fernet.decrypt(data['secret'].encode()).decode()
        os.remove(filepath)

        # If the secret is a file, serve it as a downloadable file
        if data.get("is_file"):
            file_data = base64.b64decode(decrypted)
            return send_file(
                BytesIO(file_data),
                mimetype=data["mimetype"],
                as_attachment=True,
                download_name=data["filename"]
            )
        else:
            return render_template("secret.html", secret=decrypted, is_file=False)

    # Calculate the remaining time before the secret expires
    time_remaining = expires_at - datetime.utcnow()

    # Display the confirmation page
    return render_template("confirm.html", secret_id=secret_id, time_remaining=time_remaining, password_required=data['password_hash'])

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Render uses the PORT environment variable
    app.run(host='0.0.0.0', port=port, debug=True)
