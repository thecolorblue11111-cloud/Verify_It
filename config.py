import os
import secrets

def apply_default_config(app):
    app.config['DEBUG'] = False
    app.config['TESTING'] = False
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_urlsafe(32))
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB file upload limit
