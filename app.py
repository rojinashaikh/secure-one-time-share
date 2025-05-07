from flask import Flask, render_template, request, redirect, url_for
import os
import json
import uuid
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Load environment variables from a .env file
load_dotenv()

app = Flask(__name__)

# Folder where secrets are stored
SECRETS_FOLDER = 'secrets'
os.makedirs(SECRETS_FOLDER, exist_ok=True)

# Load encryption key from environment variable (this is more secure)
FERNET_KEY = os.getenv('FERNET_KEY')

# Ensure the key is loaded properly
if not FERNET_KEY:
    raise ValueError("Encryption key not found. Make sure FERNET_KEY is set in the environment variables.")

fernet = Fernet(FERNET_KEY)

# Set expiration time for secrets (e.g., 1 hour)
EXPIRATION_TIME = timedelta(hours=1)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_secret', methods=['POST'])
def create_secret():
    secret_text = request.form.get('secret')
    if not secret_text:
        return "No secret provided.", 400

    # Encrypt the secret before saving
    encrypted_secret = fernet.encrypt(secret_text.encode()).decode()

    secret_id = str(uuid.uuid4())
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")

    # Store the current time and expiration time in the secret file
    created_at = datetime.utcnow()
    expires_at = created_at + EXPIRATION_TIME

    # Save encrypted secret and expiration time to file
    with open(filepath, 'w') as f:
        json.dump({
            "secret": encrypted_secret,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat()
        }, f)

    share_url = url_for('secret', secret_id=secret_id, _external=True)
    return render_template('share.html', url=share_url)

@app.route('/secret/<secret_id>', methods=['GET', 'POST'])
def secret(secret_id):
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")

    if not os.path.exists(filepath):
        return render_template("expired.html")

    # Load secret data from the file
    with open(filepath, 'r') as f:
        secret_data = json.load(f)

    # Parse expiration time
    expires_at = datetime.fromisoformat(secret_data['expires_at'])

    # Check if the secret has expired
    if datetime.utcnow() > expires_at:
        os.remove(filepath)  # Delete the secret if it has expired
        return render_template("expired.html")

    if request.method == 'POST':
        # On POST, reveal and delete the secret
        decrypted_secret = fernet.decrypt(secret_data['secret'].encode()).decode()

        # Remove the secret after revealing
        os.remove(filepath)

        return render_template("secret.html", secret=decrypted_secret)

    # On GET, show confirmation page
    return render_template("confirm.html", secret_id=secret_id)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Render uses PORT environment variable
    app.run(host='0.0.0.0', port=port, debug=True)
