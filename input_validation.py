import re

def is_valid_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None

def is_valid_filename(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def is_safe_string(value, max_length=255):
    if not isinstance(value, str) or len(value) > max_length:
        return False
    return all(32 <= ord(c) <= 126 for c in value)