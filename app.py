from flask import Flask, render_template, request, redirect, url_for
import os
import json
import uuid

app = Flask(__name__)

# Folder where secrets are stored
SECRETS_FOLDER = 'secrets'
os.makedirs(SECRETS_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_secret', methods=['POST'])
def create_secret():
    secret_text = request.form.get('secret')
    if not secret_text:
        return "No secret provided.", 400

    secret_id = str(uuid.uuid4())
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")

    with open(filepath, 'w') as f:
        json.dump({"secret": secret_text}, f)

    share_url = url_for('secret', secret_id=secret_id, _external=True)
    return render_template('share.html', url=share_url)

@app.route('/secret/<secret_id>', methods=['GET', 'POST'])
def secret(secret_id):
    filepath = os.path.join(SECRETS_FOLDER, f"{secret_id}.json")

    if not os.path.exists(filepath):
        return render_template("expired.html")

    if request.method == 'POST':
        # On POST, reveal and delete the secret
        with open(filepath, 'r') as f:
            secret_data = json.load(f)
        os.remove(filepath)
        return render_template("secret.html", secret=secret_data['secret'])

    # On GET, show confirmation page
    return render_template("confirm.html", secret_id=secret_id)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))  # Render uses PORT environment variable
    app.run(host='0.0.0.0', port=port, debug=True)
