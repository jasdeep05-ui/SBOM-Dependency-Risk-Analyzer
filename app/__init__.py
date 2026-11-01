"""
Flask application factory.

Usage:
    from app import create_app
    app = create_app()
"""

import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app(config_object="config"):
    """
    Create and configure the Flask application.

    Args:
        config_object: Python import path of the config module (default: 'config').

    Returns:
        Configured Flask app instance.
    """
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_object)

    # Ensure required directories exist
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["EXPORT_FOLDER"], exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "..", "instance"), exist_ok=True)

    # Initialise SQLAlchemy
    db.init_app(app)

    # Apply CORS only when CORS_ALLOWED_ORIGINS is explicitly configured
    cors_origins = app.config.get("CORS_ALLOWED_ORIGINS", [])
    if cors_origins:
        from flask_cors import CORS
        CORS(app, origins=cors_origins)

    # Register the main Blueprint (implemented in Phase 6)
    from app.routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Create database tables on first run.
    # Models must be imported before db.create_all() so SQLAlchemy
    # knows which tables to create.
    with app.app_context():
        from app import models  # noqa: F401 — side-effect import registers models
        db.create_all()

    return app
