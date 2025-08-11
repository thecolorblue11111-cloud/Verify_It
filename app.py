import os
import hashlib
import logging
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import sqlite3
import speech_recognition as sr
import io
import wave
import tempfile

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Configure upload settings
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'wav', 'mp3', 'webm', 'ogg'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

from models import User, get_user_by_id

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_verification_hash(log_data):
    """Generate SHA256 hash for log verification"""
    hash_string = f"{log_data['method']}{log_data['recipient']}{log_data['description']}{log_data['timestamp']}"
    return hashlib.sha256(hash_string.encode()).hexdigest()

def transcribe_audio(file_path):
    """Transcribe audio file using SpeechRecognition"""
    r = sr.Recognizer()
    try:
        with sr.AudioFile(file_path) as source:
            audio = r.record(source)
        text = r.recognize_google(audio)
        return text
    except Exception as e:
        logging.error(f"Transcription error: {e}")
        return "Transcription failed"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required')
            return render_template('register.html')
        
        # Check if user already exists
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE username = ? OR email = ?', (username, email))
        if cursor.fetchone():
            flash('Username or email already exists')
            conn.close()
            return render_template('register.html')
        
        # Create new user
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, datetime.now()))
        
        conn.commit()
        conn.close()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data and check_password_hash(user_data[2], password):
            user = User(user_data[0], user_data[1])
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, method, recipient, description, timestamp
        FROM logs WHERE user_id = ?
        ORDER BY timestamp DESC
    ''', (current_user.id,))
    logs = cursor.fetchall()
    conn.close()
    
    # Convert to list of dictionaries for template
    log_list = []
    for log in logs:
        log_list.append({
            'id': log[0],
            'method': log[1],
            'recipient': log[2],
            'description': log[3],
            'timestamp': log[4]
        })
    
    return render_template('dashboard.html', logs=log_list)

@app.route('/new_log')
@login_required
def new_log():
    return render_template('new_log.html')

@app.route('/create_log', methods=['POST'])
@login_required
def create_log():
    method = request.form.get('method')
    recipient = request.form.get('recipient')
    description = request.form.get('description')
    notes = request.form.get('notes', '')
    timestamp = datetime.now()
    
    if not method or not recipient or not description:
        flash('Method, recipient, and description are required')
        return redirect(url_for('new_log'))
    
    # Create user directory if it doesn't exist
    user_upload_dir = os.path.join(UPLOAD_FOLDER, str(current_user.id))
    os.makedirs(user_upload_dir, exist_ok=True)
    
    file_path = None
    audio_path = None
    transcript = None
    
    # Handle file upload
    if 'evidence_file' in request.files:
        file = request.files['evidence_file']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp_str}_{filename}"
            file_path = os.path.join(user_upload_dir, filename)
            file.save(file_path)
            file_path = f"{current_user.id}/{filename}"  # Store relative path
    
    # Handle audio recording
    if 'audio_file' in request.files:
        audio_file = request.files['audio_file']
        if audio_file and audio_file.filename:
            filename = secure_filename(audio_file.filename)
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"audio_{timestamp_str}_{filename}"
            audio_path_full = os.path.join(user_upload_dir, filename)
            audio_file.save(audio_path_full)
            audio_path = f"{current_user.id}/{filename}"  # Store relative path
            
            # Try to transcribe audio
            try:
                # Convert webm to wav if needed for transcription
                if filename.endswith('.webm'):
                    transcript = "Audio recorded (transcription not available for WebM format)"
                else:
                    transcript = transcribe_audio(audio_path_full)
            except Exception as e:
                logging.error(f"Transcription failed: {e}")
                transcript = "Transcription failed"
    
    # Generate verification hash
    log_data = {
        'method': method,
        'recipient': recipient,
        'description': description,
        'timestamp': timestamp.isoformat()
    }
    verification_hash = generate_verification_hash(log_data)
    
    # Save to database
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO logs (user_id, method, recipient, description, notes, timestamp, 
                         file_path, audio_path, transcript, verification_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (current_user.id, method, recipient, description, notes, timestamp,
          file_path, audio_path, transcript, verification_hash))
    
    conn.commit()
    conn.close()
    
    flash('Log created successfully!')
    return redirect(url_for('dashboard'))

@app.route('/log/<int:log_id>')
@login_required
def view_log(log_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, method, recipient, description, notes, timestamp,
               file_path, audio_path, transcript, verification_hash
        FROM logs WHERE id = ? AND user_id = ?
    ''', (log_id, current_user.id))
    
    log_data = cursor.fetchone()
    conn.close()
    
    if not log_data:
        flash('Log not found')
        return redirect(url_for('dashboard'))
    
    log = {
        'id': log_data[0],
        'method': log_data[1],
        'recipient': log_data[2],
        'description': log_data[3],
        'notes': log_data[4],
        'timestamp': log_data[5],
        'file_path': log_data[6],
        'audio_path': log_data[7],
        'transcript': log_data[8],
        'verification_hash': log_data[9]
    }
    
    return render_template('log_details.html', log=log)

@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    # Extract user_id from path and verify access
    if '/' in filename:
        user_id_str = filename.split('/')[0]
        try:
            file_user_id = int(user_id_str)
            if file_user_id != current_user.id:
                flash('Access denied')
                return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid file path')
            return redirect(url_for('dashboard'))
    
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/export_log/<int:log_id>')
@login_required
def export_log(log_id):
    # Simple implementation - in production, would generate proper PDF/ZIP
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT method, recipient, description, notes, timestamp, verification_hash
        FROM logs WHERE id = ? AND user_id = ?
    ''', (log_id, current_user.id))
    
    log_data = cursor.fetchone()
    conn.close()
    
    if not log_data:
        flash('Log not found')
        return redirect(url_for('dashboard'))
    
    # For now, return a simple text export
    export_text = f"""
COMMUNICATION LOG EXPORT
========================
Method: {log_data[0]}
Recipient: {log_data[1]}
Date/Time: {log_data[4]}
Description: {log_data[2]}
Notes: {log_data[3]}
Verification Hash: {log_data[5]}
========================
Generated on: {datetime.now()}
    """
    
    from flask import Response
    return Response(
        export_text,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=log_{log_id}_export.txt'}
    )

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            method TEXT NOT NULL,
            recipient TEXT NOT NULL,
            description TEXT NOT NULL,
            notes TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT,
            audio_path TEXT,
            transcript TEXT,
            verification_hash TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
