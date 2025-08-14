"""
Trust and Integrity Verification Module
Handles public verification of logs, hashes, and blockchain timestamps
"""

import hashlib
import json
import sqlite3
import subprocess
import os
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import logging

# Configure logging
verification_logger = logging.getLogger('verification')

class VerificationResult:
    """Container for verification results"""
    def __init__(self):
        self.is_valid = False
        self.log_data = None
        self.hash_verified = False
        self.timestamp_verified = False
        self.timestamp_status = None
        self.verification_details = {}
        self.errors = []
        self.warnings = []

def verify_log_hash(log_hash: str) -> VerificationResult:
    """
    Verify a log exists and its hash is valid
    
    Args:
        log_hash (str): SHA256 hash of the log to verify
    
    Returns:
        VerificationResult: Comprehensive verification results
    """
    result = VerificationResult()
    
    try:
        # Connect to database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Find log by hash
        cursor.execute('''
            SELECT id, user_id, method, recipient, description, timestamp, 
                   verification_hash, ots_file_path, ots_status, ots_created_at, ots_confirmed_at
            FROM logs WHERE verification_hash = ?
        ''', (log_hash,))
        
        log_row = cursor.fetchone()
        
        if not log_row:
            result.errors.append("Log not found with the provided hash")
            conn.close()
            return result
        
        # Extract log data
        log_id, user_id, method, recipient, description, timestamp, stored_hash, ots_file_path, ots_status, ots_created_at, ots_confirmed_at = log_row
        
        result.log_data = {
            'id': log_id,
            'method': method,
            'recipient': recipient,
            'description': description,
            'timestamp': timestamp,
            'hash': stored_hash,
            'ots_status': ots_status,
            'ots_created_at': ots_created_at,
            'ots_confirmed_at': ots_confirmed_at
        }
        
        # Verify hash matches
        if stored_hash == log_hash:
            result.hash_verified = True
            result.verification_details['hash_algorithm'] = 'SHA256'
            result.verification_details['hash_verified_at'] = datetime.now().isoformat()
        else:
            result.errors.append("Hash verification failed - stored hash doesn't match provided hash")
        
        # Verify blockchain timestamp if available
        if ots_file_path and ots_status:
            timestamp_result = verify_blockchain_timestamp(log_id, user_id, ots_file_path)
            result.timestamp_verified = timestamp_result['verified']
            result.timestamp_status = timestamp_result['status']
            result.verification_details['timestamp'] = timestamp_result
            
            if not result.timestamp_verified and ots_status == 'confirmed':
                result.warnings.append("Blockchain timestamp could not be verified at this time")
        
        # Overall verification status
        result.is_valid = result.hash_verified and (result.timestamp_verified or ots_status != 'confirmed')
        
        conn.close()
        
        verification_logger.info(f"Log verification completed for hash {log_hash[:16]}... - Valid: {result.is_valid}")
        
    except Exception as e:
        result.errors.append(f"Verification failed: {str(e)}")
        verification_logger.error(f"Log verification error for hash {log_hash[:16]}...: {e}")
    
    return result

def verify_blockchain_timestamp(log_id: int, user_id: int, ots_file_path: str) -> Dict[str, Any]:
    """
    Verify blockchain timestamp using OpenTimestamps
    
    Args:
        log_id (int): Log ID
        user_id (int): User ID
        ots_file_path (str): Path to OTS file
    
    Returns:
        Dict: Verification results
    """
    result = {
        'verified': False,
        'status': 'unknown',
        'details': {},
        'error': None
    }
    
    try:
        # Security check: ensure path is relative
        if os.path.isabs(ots_file_path):
            result['error'] = "Invalid file path"
            return result
        
        full_ots_path = os.path.join('uploads', ots_file_path)
        
        if not os.path.exists(full_ots_path):
            result['error'] = "Timestamp file not found"
            result['status'] = 'missing'
            return result
        
        # Try to upgrade timestamp first
        try:
            upgrade_result = subprocess.run(
                ['ots', 'upgrade', full_ots_path], 
                capture_output=True, text=True, timeout=30
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result['error'] = "OpenTimestamps verification unavailable"
            return result
        
        # Verify timestamp
        try:
            verify_result = subprocess.run(
                ['ots', 'verify', full_ots_path], 
                capture_output=True, text=True, timeout=30
            )
            
            result['details']['verify_output'] = verify_result.stdout
            result['details']['verify_returncode'] = verify_result.returncode
            
            if verify_result.returncode == 0 and 'Success!' in verify_result.stdout:
                result['verified'] = True
                result['status'] = 'confirmed'
                
                # Extract timestamp information
                if 'verified in the Bitcoin blockchain' in verify_result.stdout:
                    result['details']['blockchain'] = 'Bitcoin'
                    # Try to extract block information
                    lines = verify_result.stdout.split('\n')
                    for line in lines:
                        if 'block' in line.lower():
                            result['details']['block_info'] = line.strip()
                            break
            
            elif 'Pending' in verify_result.stdout:
                result['status'] = 'pending'
                result['details']['message'] = 'Timestamp is pending blockchain confirmation'
            
            else:
                result['status'] = 'failed'
                result['error'] = 'Timestamp verification failed'
        
        except subprocess.TimeoutExpired:
            result['error'] = "Verification timeout"
        
    except Exception as e:
        result['error'] = f"Verification error: {str(e)}"
        verification_logger.error(f"Blockchain timestamp verification error for log {log_id}: {e}")
    
    return result

def generate_verification_certificate(verification_result: VerificationResult) -> Dict[str, Any]:
    """
    Generate a verification certificate with all verification details
    
    Args:
        verification_result (VerificationResult): Verification results
    
    Returns:
        Dict: Certificate data
    """
    certificate = {
        'certificate_id': hashlib.sha256(f"{verification_result.log_data['hash']}{datetime.now().isoformat()}".encode()).hexdigest()[:16],
        'generated_at': datetime.now().isoformat(),
        'log_data': verification_result.log_data,
        'verification_status': {
            'overall_valid': verification_result.is_valid,
            'hash_verified': verification_result.hash_verified,
            'timestamp_verified': verification_result.timestamp_verified,
            'timestamp_status': verification_result.timestamp_status
        },
        'verification_details': verification_result.verification_details,
        'errors': verification_result.errors,
        'warnings': verification_result.warnings,
        'verification_method': 'Proof Logger Public Verification System',
        'verification_url': f"https://verify.prooflogger.com/verify/{verification_result.log_data['hash']}" if verification_result.log_data else None
    }
    
    return certificate

def create_verification_qr_code(log_hash: str) -> str:
    """
    Create QR code for easy verification sharing
    
    Args:
        log_hash (str): Log hash to create QR code for
    
    Returns:
        str: Base64 encoded QR code image
    """
    try:
        import qrcode
        import io
        import base64
        
        # Create verification URL
        verification_url = f"https://verify.prooflogger.com/verify/{log_hash}"
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=6,
            border=2,
        )
        qr.add_data(verification_url)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_b64 = base64.b64encode(buffered.getvalue()).decode()
        
        return f"data:image/png;base64,{img_b64}"
    
    except Exception as e:
        verification_logger.error(f"QR code generation failed: {e}")
        return None

def get_verification_statistics() -> Dict[str, Any]:
    """
    Get overall verification statistics for the platform
    
    Returns:
        Dict: Verification statistics
    """
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # Total logs
        cursor.execute('SELECT COUNT(*) FROM logs')
        total_logs = cursor.fetchone()[0]
        
        # Logs with blockchain timestamps
        cursor.execute('SELECT COUNT(*) FROM logs WHERE ots_status IS NOT NULL')
        timestamped_logs = cursor.fetchone()[0]
        
        # Confirmed timestamps
        cursor.execute('SELECT COUNT(*) FROM logs WHERE ots_status = "confirmed"')
        confirmed_timestamps = cursor.fetchone()[0]
        
        # Recent verifications (from audit logs)
        cursor.execute('''
            SELECT COUNT(*) FROM audit_logs 
            WHERE action = 'public_verification' 
            AND timestamp > datetime('now', '-24 hours')
        ''')
        recent_verifications = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_logs': total_logs,
            'timestamped_logs': timestamped_logs,
            'confirmed_timestamps': confirmed_timestamps,
            'recent_verifications': recent_verifications,
            'timestamp_success_rate': (confirmed_timestamps / timestamped_logs * 100) if timestamped_logs > 0 else 0
        }
    
    except Exception as e:
        verification_logger.error(f"Statistics generation failed: {e}")
        return {
            'total_logs': 0,
            'timestamped_logs': 0,
            'confirmed_timestamps': 0,
            'recent_verifications': 0,
            'timestamp_success_rate': 0
        }

def log_verification_attempt(log_hash: str, verification_result: VerificationResult, ip_address: str = None):
    """
    Log public verification attempts for analytics and security
    
    Args:
        log_hash (str): Hash that was verified
        verification_result (VerificationResult): Verification results
        ip_address (str): IP address of verifier
    
    Returns:
        dict: Log data for audit trail
    """
    return {
        'action': 'public_verification',
        'resource_type': 'log',
        'resource_id': verification_result.log_data['id'] if verification_result.log_data else None,
        'details': {
            'log_hash': log_hash[:16] + '...',  # Truncated for privacy
            'verification_successful': verification_result.is_valid,
            'hash_verified': verification_result.hash_verified,
            'timestamp_verified': verification_result.timestamp_verified,
            'ip_address': ip_address,
            'errors': len(verification_result.errors),
            'warnings': len(verification_result.warnings)
        },
        'user_id': None,  # Public verification
        'status': 'success' if verification_result.is_valid else 'failure'
    }
