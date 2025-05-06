# Secure One-Time Share

This is a Flask-based web application that allows users to share sensitive information through a one-time viewable link.

## Features

- Secret can be viewed only once
- Data is not stored permanently
- Perfect for sharing private notes

## How to Run (Locally)

1. Install dependencies:
```
pip install -r requirements.txt
```

2. Run the application:
```
python app.py
```

3. Open your browser and go to:
```
http://localhost:10000
```

## Deployment (Render)

- Upload this repo to GitHub
- Create a new Web Service on [https://render.com](https://render.com)
- Use the following settings:
  - **Build Command**: `pip install -r requirements.txt`
  - **Start Command**: `python app.py`
  - **Port**: 10000
