"""
Application configuration.

Environment variables:
  SECRET_KEY           Flask secret key (required in production)
  FLASK_ENV            Set to 'development' to enable debug mode
  CORS_ALLOWED_ORIGINS Comma-separated list of allowed CORS origins (disabled if unset)
"""

import os
import logging

# ---------------------------------------------------------------------------
# Base directory
# ---------------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ---------------------------------------------------------------------------
# Secret key
# ---------------------------------------------------------------------------
_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    _secret_key = "dev-insecure-fallback-key-change-in-production"
    logging.warning(
        "SECRET_KEY environment variable is not set. "
        "Using an insecure fallback key — do NOT use this in production."
    )

SECRET_KEY = _secret_key

# ---------------------------------------------------------------------------
# Debug mode — only enabled in development
# ---------------------------------------------------------------------------
DEBUG = os.environ.get("FLASK_ENV", "production").lower() == "development"

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "instance", "scans.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False

# ---------------------------------------------------------------------------
# File upload
# ---------------------------------------------------------------------------
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
EXPORT_FOLDER = os.path.join(BASE_DIR, "exports")

# Hard limit: 2 MB — Flask returns 413 automatically when exceeded
MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

# Only .txt (requirements.txt) and .json (package.json) are accepted
ALLOWED_EXTENSIONS = {".txt", ".json"}

# ---------------------------------------------------------------------------
# CORS — disabled by default; enable by setting CORS_ALLOWED_ORIGINS
# ---------------------------------------------------------------------------
# Provide a comma-separated list of origins, e.g.:
#   CORS_ALLOWED_ORIGINS=http://localhost:3000,https://myapp.example.com
# Leave unset (empty string) to keep CORS fully disabled.
CORS_ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
