"""
Development entry point.

Run with:
    python run.py

For production, use a proper WSGI server (gunicorn, waitress, etc.)
and set the SECRET_KEY environment variable.
"""

import os

# Guard: this file must only be used in development
if os.environ.get("FLASK_ENV", "").lower() != "development":
    import warnings
    warnings.warn(
        "run.py is intended for local development only. "
        "Set FLASK_ENV=development to suppress this warning.",
        stacklevel=1,
    )

from app import create_app

app = create_app()

if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV", "").lower() == "development"
    app.run(debug=debug, host="127.0.0.1", port=5000)
