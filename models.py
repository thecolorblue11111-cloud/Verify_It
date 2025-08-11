import sqlite3
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username
    
    def get_id(self):
        return str(self.id)

def get_user_by_id(user_id):
    """Get user by ID for Flask-Login"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    
    if user_data:
        return User(user_data[0], user_data[1])
    return None
