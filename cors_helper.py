from flask_cors import CORS

def init_cors(app):
    # Adjust origins as needed for your deployment
    CORS(app, resources={r"/api/*": {"origins": ["https://yourdomain.com"]}})