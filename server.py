import os
import json
import hashlib
import requests
import signal
import sys
import secrets
import re
from datetime import datetime, timedelta
from flask import Flask, jsonify, Response, request, make_response
from urllib.parse import urljoin
from dotenv import load_dotenv
import tokenext

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration from environment variables
PORT = int(os.getenv("PORT", "6942"))
PASSWORD = os.getenv("PASSWORD", "").strip()
CACHE_DIR = os.getenv("CACHE_DIR", "cache")
BASE_API = os.getenv("BASE_API", "https://ws1.smn.gob.ar")
LOG_FILE = os.getenv("LOG_FILE", "").strip()
BASE_PATH = os.getenv("BASE_PATH", "/smn").strip()
AUTH_ENABLED = PASSWORD != ""
CACHE_TTL = timedelta(minutes=int(os.getenv("CACHE_TTL_MINUTES", "60")))
SMN_TOKEN_FILE = os.getenv("SMN_TOKEN_FILE", "token")

# Rate limiting configuration
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "false").lower() == "true"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_STORAGE_URL = os.getenv("RATE_LIMIT_STORAGE_URL", "").strip()

# Ensure BASE_PATH is properly formatted
if not BASE_PATH.startswith("/"):
    BASE_PATH = "/" + BASE_PATH
if BASE_PATH.endswith("/"):
    BASE_PATH = BASE_PATH[:-1]

# Initialize rate limiter if enabled
limiter = None
if RATE_LIMIT_ENABLED:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    
    storage_uri = RATE_LIMIT_STORAGE_URL if RATE_LIMIT_STORAGE_URL else "memory://"
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        storage_uri=storage_uri,
        default_limits=[f"{RATE_LIMIT_REQUESTS} per {RATE_LIMIT_WINDOW_SECONDS} seconds"],
        headers_enabled=True,
    )

def sanitize_for_log(text: str) -> str:
    """Sanitize sensitive data from log messages"""
    # Mask JWT tokens
    text = re.sub(r'JWT [A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', 'JWT [REDACTED]', text)
    # Mask authorization headers
    text = re.sub(r'Authorization:\s*[^\s]+', 'Authorization: [REDACTED]', text, flags=re.IGNORECASE)
    return text

def log(msg: str):
    sanitized_msg = sanitize_for_log(msg)
    if LOG_FILE:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"[{datetime.now().isoformat()}] {sanitized_msg}\n")
        except Exception:
            pass  # Fail silently if logging fails
    print(sanitized_msg)

def get_cache_filename(url: str) -> str:
    h = hashlib.sha256(url.encode()).hexdigest()
    return os.path.join(CACHE_DIR, f"{h}.json")

def load_cache(url: str):
    path = get_cache_filename(url)
    if not os.path.exists(path):
        return None
    mtime = datetime.fromtimestamp(os.path.getmtime(path))
    if datetime.now() - mtime > CACHE_TTL:
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def save_cache(url: str, data: dict):
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = get_cache_filename(url)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log(f"[CACHE] Failed to save cache: {e}")

def load_smn_token():
    if not os.path.exists(SMN_TOKEN_FILE):
        log("[TOKEN] Token file not found — refreshing token...")
        refresh_smn_token()
        if not os.path.exists(SMN_TOKEN_FILE):
            raise FileNotFoundError("Token file could not be created.")
    with open(SMN_TOKEN_FILE, "r") as f:
        return f.read().strip()

def refresh_smn_token():
    log("[TOKEN] Refreshing SMN token...")
    headless = os.getenv("SELENIUM_HEADLESS", "true").lower() == "true"
    wait_seconds = int(os.getenv("SELENIUM_WAIT_SECONDS", "8"))
    ok = tokenext.refresh_token(output_file=SMN_TOKEN_FILE, headless=headless, wait_seconds=wait_seconds)
    if ok:
        log("[TOKEN] Token refreshed successfully.")
    else:
        log("[TOKEN] Failed to refresh token.")

def check_access_token():
    """Check access token using constant-time comparison to prevent timing attacks"""
    if not AUTH_ENABLED:
        return True
    header_token = request.headers.get("Authorization", "").strip()
    
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(header_token, PASSWORD)

def validate_path(subpath: str) -> bool:
    """Enhanced path validation to prevent traversal attacks"""
    # Check for null bytes
    if '\x00' in subpath:
        return False
    
    # Check for path traversal patterns
    if ".." in subpath:
        return False
    
    # Check for absolute paths
    if subpath.startswith("/"):
        return False
    
    # Check for encoded traversal attempts
    dangerous_patterns = [
        '%2e%2e', '%2E%2E',  # URL encoded ..
        '..%2f', '..%5c',     # Mixed encoding
        '%252e', '%252E',     # Double encoded
    ]
    subpath_lower = subpath.lower()
    for pattern in dangerous_patterns:
        if pattern in subpath_lower:
            return False
    
    # Normalize and check the path doesn't escape
    normalized = os.path.normpath(subpath)
    if normalized.startswith("..") or normalized.startswith("/"):
        return False
    
    return True

def add_security_headers(response):
    """Add security headers to response"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    # Only add HSTS if using HTTPS
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

def fetch_from_smn(url: str, retry: bool = True):
    token = load_smn_token()
    headers = {
        "Authorization": f"JWT {token}",
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=10)
    except requests.RequestException as e:
        log(f"[ERROR] Request failed: {type(e).__name__}")
        return Response("Service temporarily unavailable", status=502)

    if resp.status_code == 401 and retry:
        log("[AUTH] SMN token expired, trying to refresh...")
        refresh_smn_token()
        return fetch_from_smn(url, retry=False)

    return resp

@app.route(f"{BASE_PATH}/<path:subpath>")
def smn_proxy(subpath):
    # Authentication check
    if not check_access_token():
        log(f"[AUTH] Unauthorized access attempt from {request.remote_addr}")
        return add_security_headers(make_response(jsonify({"error": "Unauthorized"}), 401))

    # Enhanced path validation
    if not validate_path(subpath):
        log(f"[SECURITY] Invalid path attempt: {subpath[:100]}")  # Limit logged path length
        return add_security_headers(make_response(jsonify({"error": "Invalid path"}), 400))

    url = urljoin(BASE_API + "/", subpath)
    
    # Forward query parameters to upstream API
    if request.query_string:
        url += "?" + request.query_string.decode('utf-8')

    # Check cache
    cached = load_cache(url)
    if cached:
        log(f"[CACHE] Loaded {subpath[:100]}")
        return add_security_headers(make_response(jsonify(cached)))

    # Fetch from upstream
    log(f"[FETCH] Requesting data from SMN")
    resp = fetch_from_smn(url)

    if not hasattr(resp, "status_code"):
        return add_security_headers(make_response(jsonify({"error": "Service error"}), 502))

    if resp.status_code != 200:
        # Don't expose detailed upstream errors
        if resp.status_code >= 500:
            return add_security_headers(make_response(
                jsonify({"error": "Upstream service error"}), 502
            ))
        return add_security_headers(make_response(
            Response(resp.text, status=resp.status_code,
                    content_type=resp.headers.get("Content-Type", "text/plain"))
        ))

    try:
        data = resp.json()
        save_cache(url, data)
        return add_security_headers(make_response(jsonify(data)))
    except Exception:
        log("[ERROR] Invalid JSON from upstream")
        return add_security_headers(make_response(
            jsonify({"error": "Invalid response from upstream"}), 502
        ))

@app.errorhandler(404)
def handle_not_found(e):
    return add_security_headers(make_response(jsonify({
        "error": "Endpoint not found",
        "message": "The requested endpoint is not available.",
    }), 404))

@app.errorhandler(405)
def handle_method_not_allowed(e):
    return add_security_headers(make_response(jsonify({
        "error": "Method not allowed",
        "allowed": ["GET"],
    }), 405))

@app.errorhandler(429)
def handle_rate_limit_exceeded(e):
    log(f"[RATE_LIMIT] Rate limit exceeded from {request.remote_addr}")
    return add_security_headers(make_response(jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please try again later.",
    }), 429))

@app.errorhandler(Exception)
def handle_general_error(e):
    # Log detailed error server-side
    log(f"[ERROR] Unexpected exception: {type(e).__name__}: {str(e)}")
    # Return generic error to client
    return add_security_headers(make_response(jsonify({
        "error": "Internal error",
        "message": "An unexpected error occurred.",
    }), 500))

def handle_sigint(signum, frame):
    log("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_sigint)

# Initialize on startup
os.makedirs(CACHE_DIR, exist_ok=True)
if not os.path.exists(SMN_TOKEN_FILE):
    log("[STARTUP] No token file found, generating a new one.")
    refresh_smn_token()

log(f"[STARTUP] Server configured on port {PORT}")
log(f"[STARTUP] Base path set to '{BASE_PATH}/<path>'")
log(f"[STARTUP] Authentication: {'Enabled' if AUTH_ENABLED else 'Disabled'}")
log(f"[STARTUP] Rate Limiting: {'Enabled' if RATE_LIMIT_ENABLED else 'Disabled'}")
if RATE_LIMIT_ENABLED:
    log(f"[STARTUP] Rate Limit: {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW_SECONDS} seconds")
    log(f"[STARTUP] Rate Limit Storage: {RATE_LIMIT_STORAGE_URL if RATE_LIMIT_STORAGE_URL else 'memory'}")

# Wrap Flask app with ASGI adapter for uvicorn
from asgiref.wsgi import WsgiToAsgi
app = WsgiToAsgi(app)
