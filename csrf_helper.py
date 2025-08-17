from flask_wtf import CSRFProtect

def init_csrf(app):
    csrf = CSRFProtect()
    csrf.init_app(app)
