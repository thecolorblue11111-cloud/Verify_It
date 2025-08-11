# Overview

Proof Logger is a Flask-based web application designed to help users track and document communications with organizations (calls, emails, visits, texts) to maintain verifiable proof for dispute resolution. The app provides secure user authentication, audio recording capabilities, file uploads, and generates cryptographic hashes for data integrity verification.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Template Engine**: Jinja2 with Flask for server-side rendering
- **Styling**: Custom CSS with dark theme and responsive design using CSS Grid/Flexbox
- **JavaScript**: Vanilla JS for client-side interactions including WebRTC MediaRecorder API for browser-based audio recording
- **UI Framework**: Clean, mobile-first design with Feather icons integration

## Backend Architecture
- **Web Framework**: Flask with modular route handling
- **Authentication**: Flask-Login with session management and password hashing using Werkzeug
- **File Handling**: Secure file uploads with extension validation and size limits (16MB max)
- **Audio Processing**: Speech recognition using Python's SpeechRecognition library for automatic transcription
- **Security**: SHA256 hash generation for log verification and data integrity

## Data Storage
- **Database**: SQLite with three main tables:
  - `users`: User authentication and profile data
  - `logs`: Communication records with metadata and file paths
  - `sessions`: Flask-Login session management
- **File Storage**: Local filesystem storage in `/uploads` directory organized by user accounts
- **Audio Storage**: Recorded audio files stored alongside evidence files with automatic transcription

## Core Features
- **Log Management**: CRUD operations for communication logs with timestamp tracking
- **Evidence Handling**: Multi-format file upload support (images, documents, audio)
- **Audio Recording**: Browser-based recording with playback and transcription
- **Export System**: PDF and ZIP export functionality for selected logs
- **Verification**: Cryptographic hash generation for tamper-proof records
- **User Isolation**: Strict access control ensuring users only see their own data

## Security Measures
- **Input Validation**: Secure filename handling and file type restrictions
- **Authentication**: Password hashing and session-based login protection
- **Access Control**: Login-required decorators on sensitive routes
- **File Security**: Whitelist-based file extension filtering
- **Data Integrity**: SHA256 verification hashes for all log entries

# External Dependencies

## Python Packages
- **Flask**: Core web framework and routing
- **Flask-Login**: User session management and authentication
- **Werkzeug**: Password hashing and secure file handling utilities
- **SpeechRecognition**: Audio transcription and speech-to-text processing

## Frontend Libraries
- **Feather Icons**: Icon library for UI elements (CDN)
- **WebRTC MediaRecorder**: Browser API for audio recording (native)

## Database
- **SQLite**: Embedded database for user data and communication logs

## Browser APIs
- **MediaDevices API**: Microphone access for audio recording
- **File API**: Client-side file handling and preview
- **FormData API**: Multipart form submission with file uploads

## Development Tools
- **Logging**: Python logging module for debugging and monitoring
- **Tempfile**: Temporary file handling for audio processing
- **Hashlib**: Cryptographic hash generation for verification