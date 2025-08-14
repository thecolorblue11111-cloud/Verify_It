"""
Security module for Proof Logger
Implements comprehensive security hardening features
"""

import os
import hashlib
import hmac
import magic
import bleach
from datetime import datetime
from functools import wraps
from flask import request, abort, g, current_app
from werkzeug.utils import secure_filename
import logging

# Configure logging
security_logger = logging.getLogger('security')

# Allowed HTML tags and attributes for sanitization
ALLOWED_TAGS = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a']
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title'],
}

# Allowed file extensions and their corresponding MIME types
ALLOWED_FILE_TYPES = {
    'txt': ['text/plain'],
    'pdf': ['application/pdf'],
    'png': ['image/png'],
    'jpg': ['image/jpeg'],
    'jpeg': ['image/jpeg'],
    'gif': ['image/gif'],
    'webp': ['image/webp'],
    'doc': ['application/msword'],
    'docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    'wav': ['audio/wav', 'audio/x-wav'],
    'mp3': ['audio/mpeg'],
    'webm': ['audio/webm', 'video/webm'],
    'ogg': ['audio/ogg', 'application/ogg'],
}

# Maximum file sizes (in bytes)
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
MAX_TOTAL_SIZE = 64 * 1024 * 1024  # 64MB total per request

def sanitize_input(text, allow_html=False):
    """
    Sanitize user input to prevent XSS attacks
    
    Args:
        text (str): Input text to sanitize
        allow_html (bool): Whether to allow safe HTML tags
    
    Returns:
        str: Sanitized text
    """
    if not text:
        return ""
    
    if allow_html:
        # Allow safe HTML tags
        return bleach.clean(text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES, strip=True)
    else:
        # Strip all HTML
        return bleach.clean(text, tags=[], attributes={}, strip=True)

def validate_file_upload(file):
    """
    Comprehensive file upload validation
    
    Args:
        file: Flask file upload object
    
    Returns:
        tuple: (is_valid, error_message)
    """
    if not file or not file.filename:
        return False, "No file provided"
    
    # Secure the filename
    filename = secure_filename(file.filename)
    if not filename:
        return False, "Invalid filename"
    
    # Check file extension
    if '.' not in filename:
        return False, "File must have an extension"
    
    extension = filename.rsplit('.', 1)[1].lower()
    if extension not in ALLOWED_FILE_TYPES:
        return False, f"File type '{extension}' not allowed"
    
    # Check file size
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)  # Reset file pointer
    
    if file_size > MAX_FILE_SIZE:
        return False, f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB"
    
    if file_size == 0:
        return False, "File is empty"
    
    # MIME type validation using python-magic
    try:
        file_content = file.read(1024)  # Read first 1KB for MIME detection
        file.seek(0)  # Reset file pointer
        
        detected_mime = magic.from_buffer(file_content, mime=True)
        allowed_mimes = ALLOWED_FILE_TYPES.get(extension, [])
        
        if detected_mime not in allowed_mimes:
            security_logger.warning(f"MIME type mismatch: {detected_mime} not in {allowed_mimes} for {filename}")
            return False, f"File content doesn't match extension. Detected: {detected_mime}"
    
    except Exception as e:
        security_logger.error(f"MIME type detection failed for {filename}: {e}")
        return False, "Could not verify file type"
    
    return True, "File is valid"

def scan_file_for_threats(file_path):
    """
    Basic file threat scanning
    This is a placeholder for more advanced virus scanning
    
    Args:
        file_path (str): Path to the file to scan
    
    Returns:
        tuple: (is_safe, threat_info)
    """
    try:
        # Basic checks for suspicious patterns
        with open(file_path, 'rb') as f:
            content = f.read(1024)  # Read first 1KB
            
            # Check for suspicious patterns (basic implementation)
            suspicious_patterns = [
                b'<script',
                b'javascript:',
                b'vbscript:',
                b'onload=',
                b'onerror=',
                b'eval(',
                b'document.cookie',
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content.lower():
                    return False, f"Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}"
        
        return True, "File appears safe"
    
    except Exception as e:
        security_logger.error(f"File scanning failed for {file_path}: {e}")
        return False, "Could not scan file"

def generate_file_hash(file_path):
    """
    Generate SHA256 hash of a file for integrity verification
    
    Args:
        file_path (str): Path to the file
    
    Returns:
        str: SHA256 hash of the file
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        security_logger.error(f"Hash generation failed for {file_path}: {e}")
        return None

def verify_file_integrity(file_path, expected_hash):
    """
    Verify file integrity using SHA256 hash
    
    Args:
        file_path (str): Path to the file
        expected_hash (str): Expected SHA256 hash
    
    Returns:
        bool: True if file integrity is verified
    """
    actual_hash = generate_file_hash(file_path)
    if not actual_hash:
        return False
    
    return hmac.compare_digest(actual_hash, expected_hash)

def validate_input_length(text, max_length=1000):
    """
    Validate input length to prevent DoS attacks
    
    Args:
        text (str): Input text
        max_length (int): Maximum allowed length
    
    Returns:
        bool: True if length is valid
    """
    return len(str(text)) <= max_length

def validate_email_format(email):
    """
    Enhanced email validation
    
    Args:
        email (str): Email address to validate
    
    Returns:
        tuple: (is_valid, sanitized_email)
    """
    if not email:
        return False, ""
    
    # Sanitize email
    sanitized_email = sanitize_input(email.strip().lower())
    
    # Basic format validation
    if '@' not in sanitized_email or '.' not in sanitized_email:
        return False, ""
    
    # Length validation
    if len(sanitized_email) > 254:  # RFC 5321 limit
        return False, ""
    
    return True, sanitized_email

def validate_username(username):
    """
    Validate username format and content
    
    Args:
        username (str): Username to validate
    
    Returns:
        tuple: (is_valid, sanitized_username, error_message)
    """
    if not username:
        return False, "", "Username is required"
    
    # Sanitize username
    sanitized = sanitize_input(username.strip())
    
    # Length validation
    if len(sanitized) < 3:
        return False, "", "Username must be at least 3 characters"
    
    if len(sanitized) > 50:
        return False, "", "Username must be less than 50 characters"
    
    # Character validation (alphanumeric and underscore only)
    if not sanitized.replace('_', '').replace('-', '').isalnum():
        return False, "", "Username can only contain letters, numbers, hyphens, and underscores"
    
    return True, sanitized, ""

def security_headers(response):
    """
    Add security headers to response
    
    Args:
        response: Flask response object
    
    Returns:
        response: Modified response with security headers
    """
    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # HSTS (only if HTTPS)
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

def require_https():
    """
    Decorator to enforce HTTPS in production
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_app.debug and not request.is_secure:
                return abort(403, "HTTPS required")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_security_event(event_type, details, severity='INFO'):
    """
    Log security-related events
    
    Args:
        event_type (str): Type of security event
        details (dict): Event details
        severity (str): Log severity level
    """
    log_data = {
        'event_type': event_type,
        'ip_address': request.remote_addr if request else 'unknown',
        'user_agent': request.headers.get('User-Agent', 'unknown') if request else 'unknown',
        'timestamp': str(datetime.utcnow()),
        'details': details
    }
    
    if severity == 'WARNING':
        security_logger.warning(f"Security Event: {event_type} - {log_data}")
    elif severity == 'ERROR':
        security_logger.error(f"Security Event: {event_type} - {log_data}")
    else:
        security_logger.info(f"Security Event: {event_type} - {log_data}")
