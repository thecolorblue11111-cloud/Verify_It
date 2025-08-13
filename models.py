import sqlite3

class User:
    def __init__(self, id, username, password_hash=None, mfa_enabled=0, mfa_secret=None, email=None):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.mfa_enabled = mfa_enabled
        self.mfa_secret = mfa_secret
        self.email = email

    # Flask-Login required methods
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    @staticmethod
    def get_by_username(username):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, mfa_enabled, mfa_secret, email FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return User(*row)
        return None

    @staticmethod
    def get_by_id(user_id):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, mfa_enabled, mfa_secret, email FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return User(*row)
        return None

    def set_mfa(self, enabled, secret=None):
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET mfa_enabled = ?, mfa_secret = ? WHERE id = ?", (enabled, secret, self.id))
        conn.commit()
        conn.close()
        self.mfa_enabled = enabled
        self.mfa_secret = secret

def get_user_by_id(user_id):
    """Helper function for Flask-Login user_loader"""
    return User.get_by_id(user_id)
