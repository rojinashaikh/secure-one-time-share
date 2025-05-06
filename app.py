import uuid
import os
import json
from flask import Flask, render_template, request, url_for

# Path to the JSON file that stores the secrets
SECRETS_FILE = 'secrets.json'

# Function to read secrets from the file
def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Function to save secrets to the file
def save_secrets(secrets):
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_secret', methods=['POST'])
def create_secret():
    secret_content = request.form.get('secret')
    if secret_content:
        # Load existing secrets
        secrets = load_secrets()

        # Generate a new ID for the secret
        secret_id = str(uuid.uuid4())  # Generate a unique ID using UUID
        secrets[secret_id] = secret_content

        # Save the updated secrets back to the file
        save_secrets(secrets)

        # Generate the link to share
        secret_link = url_for('get_secret', secret_id=secret_id, _external=True)
        return f"Secret created! Share this link: <a href='{secret_link}'>{secret_link}</a>"

    return 'No secret provided', 400

@app.route('/secret/<secret_id>')
def get_secret(secret_id):
    secrets = load_secrets()
    secret = secrets.get(secret_id)

    if secret:
        # Delete the secret after it's viewed (one-time view)
        del secrets[secret_id]
        save_secrets(secrets)

        return render_template('show_secret.html', secret=secret)
    else:
        return "<p>This link has expired or does not exist.</p>"

if __name__ == '__main__':
    app.run(debug=True)
