from flask import Flask
from config import apply_default_config
from app.config.session import configure_session
from app.middleware.security_headers import set_security_headers
from app.config.csrf import init_csrf

def create_app():
    app = Flask(__name__)

    # Secure defaults/config
    apply_default_config(app)
    # Secure sessions
    configure_session(app)
    # Secure headers
    set_security_headers(app)
    # CSRF protection
    init_csrf(app)
    # Register blueprints, routes, etc. here

    return app
