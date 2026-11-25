"""Production WSGI entrypoint for Render/Gunicorn."""
from app import app, init_db

# Initialize/migrate database on startup (not during build).
init_db()
