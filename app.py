import os
import hashlib
import logging
import subprocess
import zipfile
import tempfile
import json
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify, send_file, after_this_request, Response
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import sqlite3
import speech_recognition as sr
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import qrcode

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

def create_opentimestamp(data_hash, log_id, user_id):
    """Create an OpenTimestamp for the given data hash"""
    try:
        # Create user timestamp directory
        timestamp_dir = os.path.join(UPLOAD_FOLDER, str(user_id), 'timestamps')
        os.makedirs(timestamp_dir, exist_ok=True)
        
        # Create a temporary file with the hash
        hash_file = os.path.join(timestamp_dir, f"log_{log_id}_hash.txt")
        with open(hash_file, 'w') as f:
            f.write(data_hash)
        
        # Create timestamp using ots command
        try:
            result = subprocess.run(['ots', 'stamp', hash_file], 
                                  capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            logging.error(f"OpenTimestamps CLI 'ots' not found for log {log_id}")
            # Mark as failed in database
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE logs SET ots_status = ? WHERE id = ? AND user_id = ?
            ''', ('failed', log_id, user_id))
            conn.commit()
            conn.close()
            return False
        
        if result.returncode == 0:
            ots_file = f"{hash_file}.ots"
            if os.path.exists(ots_file):
                # Store relative path (derive from actual ots_file path)
                relative_ots_path = os.path.relpath(ots_file, UPLOAD_FOLDER)
                
                # Update database with timestamp info
                conn = sqlite3.connect('database.db')
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE logs SET ots_file_path = ?, ots_status = ?, ots_created_at = ?
                    WHERE id = ? AND user_id = ?
                ''', (relative_ots_path, 'pending', datetime.now(), log_id, user_id))
                conn.commit()
                conn.close()
                
                logging.info(f"OpenTimestamp created for log {log_id}")
                return True
            else:
                logging.error(f"OTS file not created for log {log_id}")
                return False
        else:
            logging.error(f"OTS stamp failed for log {log_id}: {result.stderr}")
            # Mark as failed in database
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE logs SET ots_status = ? WHERE id = ? AND user_id = ?
            ''', ('failed', log_id, user_id))
            conn.commit()
            conn.close()
            return False
            
    except Exception as e:
        logging.error(f"OpenTimestamp creation failed for log {log_id}: {e}")
        # Mark as failed in database
        try:
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE logs SET ots_status = ? WHERE id = ? AND user_id = ?
            ''', ('failed', log_id, user_id))
            conn.commit()
            conn.close()
        except Exception as db_e:
            logging.error(f"Failed to update database status for log {log_id}: {db_e}")
        return False

def check_timestamp_status(log_id, user_id, ots_file_path):
    """Check and update the status of an OpenTimestamp"""
    try:
        # Security check: ensure path is relative to prevent directory traversal
        if os.path.isabs(ots_file_path):
            logging.error(f"Absolute path detected in ots_file_path: {ots_file_path}")
            return 'error'
        
        full_ots_path = os.path.join(UPLOAD_FOLDER, ots_file_path)
        if not os.path.exists(full_ots_path):
            return 'missing'
        
        # Try to upgrade the timestamp
        try:
            upgrade_result = subprocess.run(['ots', 'upgrade', full_ots_path], 
                                          capture_output=True, text=True, timeout=30)
            
            # Log upgrade issues but continue with verification
            if upgrade_result.returncode != 0:
                logging.warning(f"OTS upgrade failed for log {log_id}: {upgrade_result.stderr}")
        except FileNotFoundError:
            logging.error(f"OpenTimestamps CLI 'ots' not found for timestamp check")
            return 'error'
        
        # Check verification status
        try:
            verify_result = subprocess.run(['ots', 'verify', full_ots_path], 
                                         capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            logging.error(f"OpenTimestamps CLI 'ots' not found for timestamp verification")
            return 'error'
        
        status = 'pending'
        confirmed_at = None
        
        if verify_result.returncode == 0 and 'Success!' in verify_result.stdout:
            status = 'confirmed'
            confirmed_at = datetime.now()
        elif 'Pending' in verify_result.stdout:
            status = 'pending'
        else:
            status = 'failed'
        
        # Update database with current status
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        if confirmed_at:
            cursor.execute('''
                UPDATE logs SET ots_status = ?, ots_confirmed_at = ?
                WHERE id = ? AND user_id = ?
            ''', (status, confirmed_at, log_id, user_id))
        else:
            cursor.execute('''
                UPDATE logs SET ots_status = ? WHERE id = ? AND user_id = ?
            ''', (status, log_id, user_id))
        conn.commit()
        conn.close()
            
        return status
        
    except Exception as e:
        logging.error(f"Timestamp status check failed for log {log_id}: {e}")
        return 'error'

def get_timestamp_info(ots_file_path):
    """Get detailed information about a timestamp"""
    try:
        # Security check: ensure path is relative to prevent directory traversal
        if os.path.isabs(ots_file_path):
            logging.error(f"Absolute path detected in ots_file_path: {ots_file_path}")
            return None
        
        full_ots_path = os.path.join(UPLOAD_FOLDER, ots_file_path)
        if not os.path.exists(full_ots_path):
            return None
        
        try:
            result = subprocess.run(['ots', 'info', full_ots_path], 
                                  capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            logging.error(f"OpenTimestamps CLI 'ots' not found for timestamp info")
            return None
        
        if result.returncode == 0:
            return result.stdout
        else:
            return None
            
    except Exception as e:
        logging.error(f"Failed to get timestamp info: {e}")
        return None

# Audit Logging System
def get_client_ip():
    """Get the client's IP address, handling proxies"""
    if request.environ.get('HTTP_X_FORWARDED_FOR'):
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
    elif request.environ.get('HTTP_X_REAL_IP'):
        return request.environ['HTTP_X_REAL_IP']
    else:
        return request.environ.get('REMOTE_ADDR', 'unknown')

def get_user_agent():
    """Get the client's user agent"""
    return request.headers.get('User-Agent', 'unknown')

def create_audit_log(action, resource_type, resource_id=None, details=None, user_id=None, status='success'):
    """Create an audit log entry with tamper protection"""
    try:
        # Use current user if not specified
        if user_id is None and current_user.is_authenticated:
            user_id = current_user.id
        
        # Get the previous audit log hash for chaining
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1')
        previous_hash = cursor.fetchone()
        previous_hash = previous_hash[0] if previous_hash else '0'
        
        # Create audit log entry
        timestamp = datetime.now()
        ip_address = get_client_ip()
        user_agent = get_user_agent()
        
        # Create hash for tamper detection (chain with previous hash)
        # Use string representation to match SQLite storage format
        timestamp_str = str(timestamp)
        hash_data = f"{action}{resource_type}{resource_id}{user_id}{timestamp_str}{ip_address}{previous_hash}"
        if details:
            hash_data += json.dumps(details)
        
        audit_hash = hashlib.sha256(hash_data.encode()).hexdigest()
        
        # Store audit log
        cursor.execute('''
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id, 
                                  details, ip_address, user_agent, timestamp, 
                                  status, hash, previous_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, action, resource_type, resource_id, 
              json.dumps(details) if details else None,
              ip_address, user_agent, timestamp, status, audit_hash, previous_hash))
        
        conn.commit()
        conn.close()
        
        logging.info(f"Audit log created: {action} on {resource_type} by user {user_id}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to create audit log: {e}")
        return False

def verify_audit_chain():
    """Verify the integrity of the audit log chain"""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, user_id, action, resource_type, resource_id, details, 
                   ip_address, timestamp, hash, previous_hash
            FROM audit_logs ORDER BY id ASC
        ''')
        
        logs = cursor.fetchall()
        conn.close()
        
        if not logs:
            return True, "No audit logs to verify"
        
        expected_previous = '0'
        for log in logs:
            log_id, user_id, action, resource_type, resource_id, details, ip_address, timestamp, stored_hash, previous_hash = log
            
            # Verify previous hash chain
            if previous_hash != expected_previous:
                return False, f"Hash chain broken at log ID {log_id}"
            
            # Recalculate hash using same format as creation
            hash_data = f"{action}{resource_type}{resource_id}{user_id}{timestamp}{ip_address}{previous_hash}"
            if details:
                hash_data += details
            
            calculated_hash = hashlib.sha256(hash_data.encode()).hexdigest()
            
            if calculated_hash != stored_hash:
                return False, f"Hash mismatch at log ID {log_id} - possible tampering detected"
            
            expected_previous = stored_hash
        
        return True, f"Audit chain verified successfully ({len(logs)} entries)"
        
    except Exception as e:
        logging.error(f"Audit chain verification failed: {e}")
        return False, f"Verification error: {str(e)}"

def audit_required(action, resource_type):
    """Decorator to automatically create audit logs for route functions"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Extract resource_id from kwargs if present
            resource_id = kwargs.get('log_id') or kwargs.get('id') or kwargs.get('user_id')
            
            try:
                # Execute the original function
                result = f(*args, **kwargs)
                
                # Create audit log for successful action
                create_audit_log(
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    details={
                        'method': request.method,
                        'endpoint': request.endpoint,
                        'args': dict(request.args),
                        'form_keys': list(request.form.keys()) if request.form else []
                    },
                    status='success'
                )
                
                return result
                
            except Exception as e:
                # Create audit log for failed action
                create_audit_log(
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    details={
                        'method': request.method,
                        'endpoint': request.endpoint,
                        'error': str(e)
                    },
                    status='failure'
                )
                raise
        
        return decorated_function
    return decorator

def detect_suspicious_activity():
    """Detect potentially suspicious patterns in audit logs"""
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Check for multiple failed login attempts
        cursor.execute('''
            SELECT ip_address, COUNT(*) as attempts
            FROM audit_logs 
            WHERE action = 'login' AND status = 'failure' 
            AND timestamp > datetime('now', '-1 hour')
            GROUP BY ip_address
            HAVING attempts >= 5
        ''')
        
        suspicious_ips = cursor.fetchall()
        
        # Check for unusual access patterns
        cursor.execute('''
            SELECT user_id, COUNT(DISTINCT ip_address) as ip_count
            FROM audit_logs 
            WHERE timestamp > datetime('now', '-1 hour')
            AND user_id IS NOT NULL
            GROUP BY user_id
            HAVING ip_count >= 3
        ''')
        
        multi_ip_users = cursor.fetchall()
        
        conn.close()
        
        alerts = []
        
        for ip, attempts in suspicious_ips:
            alerts.append({
                'type': 'multiple_failed_logins',
                'ip_address': ip,
                'attempts': attempts,
                'severity': 'high'
            })
        
        for user_id, ip_count in multi_ip_users:
            alerts.append({
                'type': 'multiple_ip_access',
                'user_id': user_id,
                'ip_count': ip_count,
                'severity': 'medium'
            })
        
        return alerts
        
    except Exception as e:
        logging.error(f"Suspicious activity detection failed: {e}")
        return []

def generate_pdf_export(log_data, log_id, user_id):
    """Generate a comprehensive PDF export for a log"""
    try:
        # Create temporary file for PDF
        temp_pdf = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
        temp_pdf.close()
        
        # Create PDF document
        doc = SimpleDocTemplate(temp_pdf.name, pagesize=A4,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        # Get styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#2563eb')
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.HexColor('#1f2937')
        )
        
        # Build PDF content
        story = []
        
        # Title
        story.append(Paragraph("COMMUNICATION LOG REPORT", title_style))
        story.append(Spacer(1, 20))
        
        # Basic Information Table
        basic_data = [
            ['Method:', log_data['method']],
            ['Recipient:', log_data['recipient']],
            ['Date/Time:', log_data['timestamp']],
            ['Log ID:', str(log_id)]
        ]
        
        basic_table = Table(basic_data, colWidths=[2*inch, 4*inch])
        basic_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(basic_table)
        story.append(Spacer(1, 20))
        
        # Description
        story.append(Paragraph("Description", heading_style))
        story.append(Paragraph(log_data['description'], styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Notes (if any)
        if log_data['notes']:
            story.append(Paragraph("Notes", heading_style))
            story.append(Paragraph(log_data['notes'], styles['Normal']))
            story.append(Spacer(1, 15))
        
        # Transcript (if any)
        if log_data['transcript']:
            story.append(Paragraph("Audio Transcript", heading_style))
            story.append(Paragraph(log_data['transcript'], styles['Normal']))
            story.append(Spacer(1, 15))
        
        # Verification Information
        story.append(Paragraph("Cryptographic Verification", heading_style))
        
        verification_data = [
            ['Verification Hash:', log_data['verification_hash']],
        ]
        
        # Add blockchain information
        blockchain_status = log_data.get('ots_status', 'none')
        if blockchain_status == 'confirmed':
            verification_data.extend([
                ['Blockchain Status:', '✓ CONFIRMED on Bitcoin blockchain'],
                ['Timestamp Created:', log_data.get('ots_created_at', 'Unknown')[:16] if log_data.get('ots_created_at') else 'Unknown'],
                ['Blockchain Confirmed:', log_data.get('ots_confirmed_at', 'Unknown')[:16] if log_data.get('ots_confirmed_at') else 'Unknown'],
            ])
        elif blockchain_status == 'pending':
            verification_data.extend([
                ['Blockchain Status:', '⏳ PENDING blockchain confirmation'],
                ['Timestamp Created:', log_data.get('ots_created_at', 'Unknown')[:16] if log_data.get('ots_created_at') else 'Unknown'],
            ])
        elif blockchain_status == 'failed':
            verification_data.append(['Blockchain Status:', '✗ FAILED'])
        else:
            verification_data.append(['Blockchain Status:', '- NONE'])
        
        verification_table = Table(verification_data, colWidths=[2*inch, 4*inch])
        verification_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e5e7eb')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(verification_table)
        story.append(Spacer(1, 20))
        
        # Generate QR code for verification
        qr_data = f"Log ID: {log_id}\nHash: {log_data['verification_hash']}\nGenerated: {datetime.now().isoformat()}"
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_data)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        qr_temp = tempfile.NamedTemporaryFile(delete=False, suffix='.png')
        qr_img.save(qr_temp.name)
        qr_temp.close()
        
        # Add QR code to PDF
        story.append(Paragraph("Verification QR Code", heading_style))
        story.append(RLImage(qr_temp.name, width=1.5*inch, height=1.5*inch))
        story.append(Spacer(1, 15))
        
        # Footer information
        story.append(Spacer(1, 20))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#6b7280'),
            alignment=TA_CENTER
        )
        
        story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))
        story.append(Paragraph("This document contains cryptographic proof of data integrity.", footer_style))
        story.append(Paragraph("Blockchain timestamps provide tamper-proof evidence via OpenTimestamps.org", footer_style))
        
        # Build PDF
        doc.build(story)
        
        # Clean up QR code temp file after PDF is built
        try:
            os.unlink(qr_temp.name)
        except:
            pass
        
        return temp_pdf.name
        
    except Exception as e:
        logging.error(f"PDF generation failed: {e}")
        return None

def generate_zip_export(log_data, log_id, user_id):
    """Generate a comprehensive ZIP export with all evidence files"""
    try:
        # Create temporary file for ZIP
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_zip.close()
        
        pdf_path = None
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add PDF report
            pdf_path = generate_pdf_export(log_data, log_id, user_id)
            if pdf_path:
                zipf.write(pdf_path, f"log_{log_id}_report.pdf")
            
            # Add evidence files
            if log_data.get('file_path'):
                file_full_path = os.path.join(UPLOAD_FOLDER, log_data['file_path'])
                if os.path.exists(file_full_path):
                    # Get original filename
                    original_name = os.path.basename(log_data['file_path'])
                    zipf.write(file_full_path, f"evidence/{original_name}")
            
            # Add audio files
            if log_data.get('audio_path'):
                audio_full_path = os.path.join(UPLOAD_FOLDER, log_data['audio_path'])
                if os.path.exists(audio_full_path):
                    original_name = os.path.basename(log_data['audio_path'])
                    zipf.write(audio_full_path, f"audio/{original_name}")
            
            # Add timestamp proof file
            if log_data.get('ots_file_path'):
                ots_full_path = os.path.join(UPLOAD_FOLDER, log_data['ots_file_path'])
                if os.path.exists(ots_full_path):
                    zipf.write(ots_full_path, f"blockchain/log_{log_id}_timestamp.ots")
                
                # Add the hash file too
                hash_file_path = ots_full_path.replace('.ots', '')
                if os.path.exists(hash_file_path):
                    zipf.write(hash_file_path, f"blockchain/log_{log_id}_hash.txt")
            
            # Create verification instructions
            instructions = f"""VERIFICATION INSTRUCTIONS
========================

This package contains complete evidence for Communication Log #{log_id}

CONTENTS:
- log_{log_id}_report.pdf: Comprehensive formatted report
- evidence/: Original uploaded files
- audio/: Audio recordings
- blockchain/: OpenTimestamps blockchain proof files

VERIFICATION STEPS:

1. HASH VERIFICATION:
   - The verification hash is: {log_data['verification_hash']}
   - This SHA256 hash proves data integrity

2. BLOCKCHAIN VERIFICATION (if available):
   - Install OpenTimestamps client: pip install opentimestamps-client
   - Verify timestamp: ots verify blockchain/log_{log_id}_timestamp.ots
   - This proves the data existed at the recorded time

3. INDEPENDENT VERIFICATION:
   - All files can be independently verified
   - Hash can be recalculated from original data
   - Blockchain proof is publicly verifiable

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
System: Verify_It Communication Logger
Learn more: https://opentimestamps.org
"""
            
            zipf.writestr("README.txt", instructions)
        
        # Clean up temp PDF after ZIP is closed
        if pdf_path:
            try:
                os.unlink(pdf_path)
            except:
                pass
        
        return temp_zip.name
        
    except Exception as e:
        logging.error(f"ZIP generation failed: {e}")
        return None

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
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Create audit log for successful registration
        create_audit_log(
            action='register',
            resource_type='user',
            resource_id=user_id,
            details={'username': username, 'email': email},
            user_id=user_id,
            status='success'
        )
        
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
            
            # Create audit log for successful login
            create_audit_log(
                action='login',
                resource_type='user',
                resource_id=user_data[0],
                details={'username': username},
                user_id=user_data[0],
                status='success'
            )
            
            return redirect(url_for('dashboard'))
        else:
            # Create audit log for failed login attempt
            create_audit_log(
                action='login',
                resource_type='user',
                details={'username': username, 'reason': 'invalid_credentials'},
                user_id=None,
                status='failure'
            )
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Create audit log for logout
    create_audit_log(
        action='logout',
        resource_type='user',
        resource_id=current_user.id,
        status='success'
    )
    
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
@audit_required('view', 'dashboard')
def dashboard():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, method, recipient, description, timestamp, ots_status
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
            'timestamp': log[4],
            'ots_status': log[5] or 'none'
        })
    
    return render_template('dashboard.html', logs=log_list)

@app.route('/new_log')
@login_required
def new_log():
    return render_template('new_log.html')

@app.route('/create_log', methods=['POST'])
@login_required
@audit_required('create', 'log')
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
    log_id = cursor.lastrowid
    conn.close()
    
    # Create OpenTimestamp for the log
    try:
        success = create_opentimestamp(verification_hash, log_id, current_user.id)
        if success:
            flash('Log created successfully with blockchain timestamp!')
        else:
            flash('Log created successfully, but blockchain timestamping failed.')
    except Exception as e:
        logging.error(f"Failed to create timestamp for log {log_id}: {e}")
        flash('Log created successfully, but blockchain timestamping failed.')
    
    return redirect(url_for('dashboard'))

@app.route('/log/<int:log_id>')
@login_required
@audit_required('view', 'log')
def view_log(log_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, method, recipient, description, notes, timestamp,
               file_path, audio_path, transcript, verification_hash,
               ots_file_path, ots_status, ots_created_at, ots_confirmed_at
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
        'verification_hash': log_data[9],
        'ots_file_path': log_data[10],
        'ots_status': log_data[11],
        'ots_created_at': log_data[12],
        'ots_confirmed_at': log_data[13]
    }
    
    # Get timestamp info if available
    if log['ots_file_path']:
        log['ots_info'] = get_timestamp_info(log['ots_file_path'])
    else:
        log['ots_info'] = None
    
    return render_template('log_details.html', log=log)

@app.route('/check_timestamp/<int:log_id>')
@login_required
def check_timestamp(log_id):
    """Check and update the status of a log's timestamp"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT ots_file_path FROM logs WHERE id = ? AND user_id = ?
    ''', (log_id, current_user.id))
    
    result = cursor.fetchone()
    conn.close()
    
    if not result or not result[0]:
        flash('No timestamp found for this log')
        return redirect(url_for('view_log', log_id=log_id))
    
    ots_file_path = result[0]
    status = check_timestamp_status(log_id, current_user.id, ots_file_path)
    
    status_messages = {
        'confirmed': 'Timestamp confirmed on Bitcoin blockchain!',
        'pending': 'Timestamp is still pending blockchain confirmation',
        'failed': 'Timestamp verification failed',
        'missing': 'Timestamp file is missing',
        'error': 'Error checking timestamp status'
    }
    
    flash(status_messages.get(status, 'Unknown timestamp status'))
    return redirect(url_for('view_log', log_id=log_id))

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

def get_log_data_for_export(log_id, user_id):
    """Helper function to get complete log data for export"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, method, recipient, description, notes, timestamp,
               file_path, audio_path, transcript, verification_hash,
               ots_file_path, ots_status, ots_created_at, ots_confirmed_at
        FROM logs WHERE id = ? AND user_id = ?
    ''', (log_id, user_id))
    
    log_data = cursor.fetchone()
    conn.close()
    
    if not log_data:
        return None
    
    return {
        'id': log_data[0],
        'method': log_data[1],
        'recipient': log_data[2],
        'description': log_data[3],
        'notes': log_data[4],
        'timestamp': log_data[5],
        'file_path': log_data[6],
        'audio_path': log_data[7],
        'transcript': log_data[8],
        'verification_hash': log_data[9],
        'ots_file_path': log_data[10],
        'ots_status': log_data[11],
        'ots_created_at': log_data[12],
        'ots_confirmed_at': log_data[13]
    }

@app.route('/export_log/<int:log_id>')
@login_required
def export_log(log_id):
    """Default export - redirect to text export for backward compatibility"""
    return redirect(url_for('export_log_text', log_id=log_id))

@app.route('/export_log/<int:log_id>/text')
@login_required
@audit_required('export', 'log')
def export_log_text(log_id):
    """Export log as text file"""
    log_data = get_log_data_for_export(log_id, current_user.id)
    if not log_data:
        flash('Log not found')
        return redirect(url_for('dashboard'))
    
    # Create comprehensive export with blockchain timestamp info
    blockchain_status = log_data.get('ots_status', 'none')
    blockchain_info = ""
    
    if blockchain_status == 'confirmed':
        created_at = str(log_data.get('ots_created_at', 'Unknown'))[:16] if log_data.get('ots_created_at') else 'Unknown'
        confirmed_at = str(log_data.get('ots_confirmed_at', 'Unknown'))[:16] if log_data.get('ots_confirmed_at') else 'Unknown'
        blockchain_info = f"""
Blockchain Status: ✓ CONFIRMED on Bitcoin blockchain
Timestamp Created: {created_at}
Blockchain Confirmed: {confirmed_at}
Verification: Cryptographically proven via OpenTimestamps"""
    elif blockchain_status == 'pending':
        created_at = str(log_data.get('ots_created_at', 'Unknown'))[:16] if log_data.get('ots_created_at') else 'Unknown'
        blockchain_info = f"""
Blockchain Status: ⏳ PENDING blockchain confirmation
Timestamp Created: {created_at}
Verification: Submitted to Bitcoin blockchain, awaiting confirmation"""
    elif blockchain_status == 'failed':
        blockchain_info = f"""
Blockchain Status: ✗ FAILED
Verification: Blockchain timestamping encountered an error"""
    else:
        blockchain_info = f"""
Blockchain Status: - NONE
Verification: No blockchain timestamp available"""

    export_text = f"""
COMMUNICATION LOG EXPORT
========================
Method: {log_data['method']}
Recipient: {log_data['recipient']}
Date/Time: {log_data['timestamp']}
Description: {log_data['description']}
Notes: {log_data['notes'] or 'None'}
Verification Hash: {log_data['verification_hash']}{blockchain_info}
========================
Generated on: {datetime.now()}

This export contains cryptographic proof of data integrity.
The verification hash can be independently verified.
Blockchain timestamps provide tamper-proof evidence of existence.
Learn more: https://opentimestamps.org
    """
    
    return Response(
        export_text,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=log_{log_id}_export.txt'}
    )

@app.route('/export_log/<int:log_id>/pdf')
@login_required
@audit_required('export', 'log')
def export_log_pdf(log_id):
    """Export log as PDF file"""
    log_data = get_log_data_for_export(log_id, current_user.id)
    if not log_data:
        flash('Log not found')
        return redirect(url_for('dashboard'))
    
    pdf_path = generate_pdf_export(log_data, log_id, current_user.id)
    if not pdf_path:
        flash('Failed to generate PDF export')
        return redirect(url_for('view_log', log_id=log_id))
    
    @after_this_request
    def cleanup(response):
        try:
            os.unlink(pdf_path)
        except:
            pass
        return response
    
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f'log_{log_id}_report.pdf',
        mimetype='application/pdf'
    )

@app.route('/export_log/<int:log_id>/zip')
@login_required
@audit_required('export', 'log')
def export_log_zip(log_id):
    """Export log as ZIP file with all evidence"""
    log_data = get_log_data_for_export(log_id, current_user.id)
    if not log_data:
        flash('Log not found')
        return redirect(url_for('dashboard'))
    
    zip_path = generate_zip_export(log_data, log_id, current_user.id)
    if not zip_path:
        flash('Failed to generate ZIP export')
        return redirect(url_for('view_log', log_id=log_id))
    
    @after_this_request
    def cleanup(response):
        try:
            os.unlink(zip_path)
        except:
            pass
        return response
    
    return send_file(
        zip_path,
        as_attachment=True,
        download_name=f'log_{log_id}_evidence_package.zip',
        mimetype='application/zip'
    )

# Admin routes for audit log management
@app.route('/admin/audit_logs')
@login_required
def admin_audit_logs():
    """Admin interface for viewing audit logs"""
    # For now, allow any authenticated user to view audit logs
    # In production, you might want to add role-based access control
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    # Get filter parameters
    action_filter = request.args.get('action', '')
    user_filter = request.args.get('user', '')
    status_filter = request.args.get('status', '')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Build query with filters
    where_conditions = []
    params = []
    
    if action_filter:
        where_conditions.append('action = ?')
        params.append(action_filter)
    
    if user_filter:
        where_conditions.append('user_id = ?')
        params.append(user_filter)
    
    if status_filter:
        where_conditions.append('status = ?')
        params.append(status_filter)
    
    where_clause = ' WHERE ' + ' AND '.join(where_conditions) if where_conditions else ''
    
    # Get audit logs with pagination
    cursor.execute(f'''
        SELECT a.id, a.user_id, u.username, a.action, a.resource_type, 
               a.resource_id, a.ip_address, a.timestamp, a.status, a.details
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        {where_clause}
        ORDER BY a.timestamp DESC
        LIMIT ? OFFSET ?
    ''', params + [per_page, offset])
    
    audit_logs = cursor.fetchall()
    
    # Get total count for pagination
    cursor.execute(f'''
        SELECT COUNT(*) FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        {where_clause}
    ''', params)
    
    total_count = cursor.fetchone()[0]
    
    # Get unique actions for filter dropdown
    cursor.execute('SELECT DISTINCT action FROM audit_logs ORDER BY action')
    actions = [row[0] for row in cursor.fetchall()]
    
    # Get users for filter dropdown
    cursor.execute('SELECT id, username FROM users ORDER BY username')
    users = cursor.fetchall()
    
    conn.close()
    
    # Convert to list of dictionaries
    log_list = []
    for log in audit_logs:
        details = json.loads(log[9]) if log[9] else {}
        log_list.append({
            'id': log[0],
            'user_id': log[1],
            'username': log[2] or 'Anonymous',
            'action': log[3],
            'resource_type': log[4],
            'resource_id': log[5],
            'ip_address': log[6],
            'timestamp': log[7],
            'status': log[8],
            'details': details
        })
    
    # Calculate pagination info
    total_pages = (total_count + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages
    
    return render_template('admin/audit_logs.html', 
                         audit_logs=log_list,
                         page=page,
                         total_pages=total_pages,
                         has_prev=has_prev,
                         has_next=has_next,
                         actions=actions,
                         users=users,
                         current_filters={
                             'action': action_filter,
                             'user': user_filter,
                             'status': status_filter
                         })

@app.route('/admin/audit_verify')
@login_required
def admin_audit_verify():
    """Verify the integrity of the audit log chain"""
    create_audit_log(
        action='verify_audit_chain',
        resource_type='audit_logs',
        status='success'
    )
    
    is_valid, message = verify_audit_chain()
    
    if is_valid:
        flash(f'✅ {message}', 'success')
    else:
        flash(f'❌ {message}', 'error')
    
    return redirect(url_for('admin_audit_logs'))

@app.route('/admin/security_alerts')
@login_required
def admin_security_alerts():
    """View security alerts and suspicious activity"""
    create_audit_log(
        action='view_security_alerts',
        resource_type='security',
        status='success'
    )
    
    alerts = detect_suspicious_activity()
    
    return render_template('admin/security_alerts.html', alerts=alerts)

@app.route('/api/audit_log/<int:log_id>')
@login_required
def api_audit_log_details(log_id):
    """API endpoint to get detailed audit log information"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.id, a.user_id, u.username, a.action, a.resource_type, 
               a.resource_id, a.details, a.ip_address, a.user_agent, 
               a.timestamp, a.status, a.hash, a.previous_hash
        FROM audit_logs a
        LEFT JOIN users u ON a.user_id = u.id
        WHERE a.id = ?
    ''', (log_id,))
    
    log_data = cursor.fetchone()
    conn.close()
    
    if not log_data:
        return jsonify({'error': 'Audit log not found'}), 404
    
    details = json.loads(log_data[6]) if log_data[6] else {}
    
    return jsonify({
        'id': log_data[0],
        'user_id': log_data[1],
        'username': log_data[2] or 'Anonymous',
        'action': log_data[3],
        'resource_type': log_data[4],
        'resource_id': log_data[5],
        'details': details,
        'ip_address': log_data[7],
        'user_agent': log_data[8],
        'timestamp': log_data[9],
        'status': log_data[10],
        'hash': log_data[11],
        'previous_hash': log_data[12]
    })

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
            ots_file_path TEXT,
            ots_status TEXT DEFAULT 'pending',
            ots_created_at DATETIME,
            ots_confirmed_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Add OpenTimestamps columns to existing logs table if they don't exist
    # (Only needed for existing databases that don't have these columns)
    try:
        cursor.execute('ALTER TABLE logs ADD COLUMN ots_file_path TEXT')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE logs ADD COLUMN ots_status TEXT DEFAULT \'pending\'')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE logs ADD COLUMN ots_created_at DATETIME')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    try:
        cursor.execute('ALTER TABLE logs ADD COLUMN ots_confirmed_at DATETIME')
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Create audit_logs table for tamper-proof activity tracking
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id INTEGER,
            details TEXT,
            ip_address TEXT NOT NULL,
            user_agent TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'success',
            hash TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create index for efficient audit log queries
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)
    ''')
    
    conn.commit()
    conn.close()

# Initialize database on startup
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
