# Security Review Checklist

- [x] HTTP security headers present on all responses
- [x] Session cookies are secure, HTTPOnly, and SameSite
- [x] CSRF protection enabled globally
- [x] Input validation on all user input
- [x] File uploads restricted and sanitized
- [x] Logging does not leak secrets or sensitive data
- [x] Flask debug is disabled and secret key is strong
- [x] CORS limited to trusted origins (if API)
- [x] All dependencies are pinned and up-to-date
- [x] Automated tests cover security controls

**Review this checklist before any deployment.**