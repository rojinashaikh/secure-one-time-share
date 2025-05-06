import os
import json
import uuid
from flask import Flask, request, render_template, url_for

app = Flask(__name__)
SECRETS_FILE = 'secrets.json'

# Utility: Load secrets from file
def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Utility: Save secrets to file
def save_secrets(secrets):
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f)

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Handle secret creation
@app.route('/create_secret', methods=['POST'])
def create_secret():
    secret_content = request.form.get('secret')
    if not secret_content:
        return 'No secret provided', 400

    secrets = load_secrets()
    secret_id = str(uuid.uuid4())
    secrets[secret_id] = secret_content
    save_secrets(secrets)

    secret_link = url_for('get_secret', secret_id=secret_id, _external=True)
    return render_template('link_created.html', link=secret_link)

# Handle secret retrieval
@app.route('/secret/<secret_id>')
def get_secret(secret_id):
    secrets = load_secrets()
    secret = secrets.get(secret_id)

    if secret:
        # Delete after first view
        del secrets[secret_id]
        save_secrets(secrets)
        return render_template('show_secret.html', secret=secret)
    else:
        return render_template('not_found.html'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
