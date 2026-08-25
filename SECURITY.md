# Security Review

M & M Lab is designed for an isolated local lab. Scanning endpoints accept only loopback, private, or link-local IP addresses and perform TCP connectivity checks only.

Application controls include Werkzeug password hashing, signed Flask sessions, CSRF tokens, parameterized SQLite queries, output escaping in the event feed, login throttling, security headers, role authorization, environment-based secrets, and audit records for security-sensitive actions.

Before deployment, set a strong `SECRET_KEY` and `DASHBOARD_PASSWORD`, keep `.env` private, run behind a TLS-terminating reverse proxy, replace demo accounts, and use a production WSGI server. Threat-intelligence enrichment is offline by default; any external provider should use an API key from environment configuration and avoid sending sensitive lab data.
