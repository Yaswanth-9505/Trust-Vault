"""WSGI entry point: `gunicorn wsgi:app`, or point PythonAnywhere's WSGI file here."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Local development only. Never use the Flask dev server in production.
    app.run(host="127.0.0.1", port=5000, debug=False)
