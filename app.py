from flask import Flask, request, render_template
import uuid

app = Flask(__name__)
storage = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
def create():
    secret = request.form['secret']
    secret_id = str(uuid.uuid4())
    storage[secret_id] = secret
    return f"Share this link: <a href='/secret/{secret_id}'>https://your-app.onrender.com/secret/{secret_id}</a>"

@app.route('/secret/<secret_id>')
def get_secret(secret_id):
    secret = storage.pop(secret_id, None)
    if secret:
        return f"<h2>Your Secret:</h2><p>{secret}</p>"
    else:
        return "<p>This link has expired or does not exist.</p>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
