"""
Flask-WTF forms with CSRF protection and validation
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, TextAreaField, PasswordField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, Email, ValidationError, Optional
from wtforms.widgets import TextArea
from security import sanitize_input, validate_username, validate_email_format
import re

class SecureTextAreaWidget(TextArea):
    """Custom TextArea widget with input sanitization"""
    def __call__(self, field, **kwargs):
        if field.data:
            field.data = sanitize_input(field.data, allow_html=True)
        return super().__call__(field, **kwargs)

class LoginForm(FlaskForm):
    """Secure login form with CSRF protection"""
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=1, max=200, message="Password too long")
    ])
    
    def validate_username(self, field):
        is_valid, sanitized, error = validate_username(field.data)
        if not is_valid:
            raise ValidationError(error)
        field.data = sanitized

class RegistrationForm(FlaskForm):
    """Secure registration form with comprehensive validation"""
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=3, max=50, message="Username must be between 3 and 50 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address"),
        Length(max=254, message="Email address too long")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, max=200, message="Password must be at least 8 characters long")
    ])
    
    def validate_username(self, field):
        is_valid, sanitized, error = validate_username(field.data)
        if not is_valid:
            raise ValidationError(error)
        field.data = sanitized
    
    def validate_email(self, field):
        is_valid, sanitized = validate_email_format(field.data)
        if not is_valid:
            raise ValidationError("Please enter a valid email address")
        field.data = sanitized
    
    def validate_password(self, field):
        """Enhanced password validation"""
        password = field.data
        
        # Check for minimum complexity
        if not re.search(r'[A-Za-z]', password):
            raise ValidationError("Password must contain at least one letter")
        
        if not re.search(r'\d', password):
            raise ValidationError("Password must contain at least one number")
        
        # Check for common weak passwords
        weak_passwords = ['password', '12345678', 'qwerty123', 'admin123']
        if password.lower() in weak_passwords:
            raise ValidationError("Password is too common. Please choose a stronger password")

class LogCreationForm(FlaskForm):
    """Secure form for creating communication logs"""
    method = SelectField('Communication Method', validators=[
        DataRequired(message="Please select a communication method")
    ], choices=[
        ('', 'Select Method...'),
        ('email', 'Email'),
        ('phone', 'Phone Call'),
        ('sms', 'SMS/Text Message'),
        ('letter', 'Physical Letter'),
        ('meeting', 'In-Person Meeting'),
        ('video_call', 'Video Call'),
        ('chat', 'Online Chat'),
        ('other', 'Other')
    ])
    
    recipient = StringField('Recipient', validators=[
        DataRequired(message="Recipient is required"),
        Length(min=1, max=200, message="Recipient name must be between 1 and 200 characters")
    ])
    
    description = TextAreaField('Description', validators=[
        DataRequired(message="Description is required"),
        Length(min=10, max=5000, message="Description must be between 10 and 5000 characters")
    ], widget=SecureTextAreaWidget())
    
    tags = StringField('Tags (comma-separated)', validators=[
        Optional(),
        Length(max=500, message="Tags too long")
    ])
    
    files = FileField('Attach Files', validators=[
        Optional(),
        FileAllowed(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'doc', 'docx', 'wav', 'mp3', 'webm', 'ogg'],
                   'Invalid file type')
    ])
    
    auto_timestamp = BooleanField('Automatically create blockchain timestamp', default=True)
    
    def validate_recipient(self, field):
        field.data = sanitize_input(field.data)
    
    def validate_description(self, field):
        field.data = sanitize_input(field.data, allow_html=True)
    
    def validate_tags(self, field):
        if field.data:
            # Sanitize and validate tags
            tags = [sanitize_input(tag.strip()) for tag in field.data.split(',')]
            tags = [tag for tag in tags if tag]  # Remove empty tags
            
            if len(tags) > 20:
                raise ValidationError("Maximum 20 tags allowed")
            
            for tag in tags:
                if len(tag) > 50:
                    raise ValidationError("Each tag must be less than 50 characters")
                if not re.match(r'^[a-zA-Z0-9_\-\s]+$', tag):
                    raise ValidationError("Tags can only contain letters, numbers, spaces, hyphens, and underscores")
            
            field.data = ', '.join(tags)

class MFASetupForm(FlaskForm):
    """Form for MFA setup with token verification"""
    secret = HiddenField('Secret', validators=[DataRequired()])
    token = StringField('6-digit Code', validators=[
        DataRequired(message="Please enter the 6-digit code"),
        Length(min=6, max=6, message="Code must be exactly 6 digits")
    ])
    
    def validate_token(self, field):
        if not field.data.isdigit():
            raise ValidationError("Code must contain only numbers")

class MFAVerifyForm(FlaskForm):
    """Form for MFA verification during login"""
    token = StringField('6-digit Code', validators=[
        DataRequired(message="Please enter the 6-digit code"),
        Length(min=6, max=6, message="Code must be exactly 6 digits")
    ])
    
    def validate_token(self, field):
        if not field.data.isdigit():
            raise ValidationError("Code must contain only numbers")

class SearchForm(FlaskForm):
    """Advanced search form for logs"""
    query = StringField('Search Query', validators=[
        Optional(),
        Length(max=200, message="Search query too long")
    ])
    
    method = SelectField('Method', validators=[Optional()], choices=[
        ('', 'All Methods'),
        ('email', 'Email'),
        ('phone', 'Phone Call'),
        ('sms', 'SMS/Text Message'),
        ('letter', 'Physical Letter'),
        ('meeting', 'In-Person Meeting'),
        ('video_call', 'Video Call'),
        ('chat', 'Online Chat'),
        ('other', 'Other')
    ])
    
    tags = StringField('Tags', validators=[
        Optional(),
        Length(max=200, message="Tags filter too long")
    ])
    
    date_from = StringField('From Date (YYYY-MM-DD)', validators=[Optional()])
    date_to = StringField('To Date (YYYY-MM-DD)', validators=[Optional()])
    
    verification_status = SelectField('Verification Status', validators=[Optional()], choices=[
        ('', 'All'),
        ('verified', 'Verified'),
        ('unverified', 'Unverified'),
        ('pending', 'Pending')
    ])
    
    def validate_query(self, field):
        if field.data:
            field.data = sanitize_input(field.data)
    
    def validate_tags(self, field):
        if field.data:
            field.data = sanitize_input(field.data)
    
    def validate_date_from(self, field):
        if field.data:
            try:
                from datetime import datetime
                datetime.strptime(field.data, '%Y-%m-%d')
            except ValueError:
                raise ValidationError("Please enter date in YYYY-MM-DD format")
    
    def validate_date_to(self, field):
        if field.data:
            try:
                from datetime import datetime
                datetime.strptime(field.data, '%Y-%m-%d')
            except ValueError:
                raise ValidationError("Please enter date in YYYY-MM-DD format")

class PublicVerificationForm(FlaskForm):
    """Form for public log verification"""
    log_hash = StringField('Log Hash', validators=[
        DataRequired(message="Please enter the log hash"),
        Length(min=64, max=64, message="Hash must be exactly 64 characters")
    ])
    
    def validate_log_hash(self, field):
        if not re.match(r'^[a-fA-F0-9]{64}$', field.data):
            raise ValidationError("Invalid hash format. Must be 64 hexadecimal characters")
        field.data = field.data.lower()

class ContactForm(FlaskForm):
    """Contact form for support/feedback"""
    name = StringField('Name', validators=[
        DataRequired(message="Name is required"),
        Length(min=2, max=100, message="Name must be between 2 and 100 characters")
    ])
    
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address")
    ])
    
    subject = StringField('Subject', validators=[
        DataRequired(message="Subject is required"),
        Length(min=5, max=200, message="Subject must be between 5 and 200 characters")
    ])
    
    message = TextAreaField('Message', validators=[
        DataRequired(message="Message is required"),
        Length(min=20, max=2000, message="Message must be between 20 and 2000 characters")
    ], widget=SecureTextAreaWidget())
    
    def validate_name(self, field):
        field.data = sanitize_input(field.data)
    
    def validate_email(self, field):
        is_valid, sanitized = validate_email_format(field.data)
        if not is_valid:
            raise ValidationError("Please enter a valid email address")
        field.data = sanitized
    
    def validate_subject(self, field):
        field.data = sanitize_input(field.data)
    
    def validate_message(self, field):
        field.data = sanitize_input(field.data, allow_html=True)
