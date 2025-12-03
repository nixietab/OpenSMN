import os
import json
import hashlib
import requests
import signal
import sys
from datetime import datetime, timedelta
from flask import Flask, jsonify, Response, request
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

# Ensure BASE_PATH is properly formatted
if not BASE_PATH.startswith("/"):
    BASE_PATH = "/" + BASE_PATH
if BASE_PATH.endswith("/"):
    BASE_PATH = BASE_PATH[:-1]

def log(msg: str):
    if LOG_FILE:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] {msg}\n")
    print(msg)

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
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

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
    if not AUTH_ENABLED:
        return True
    header_token = request.headers.get("Authorization", "").strip()
    return header_token == PASSWORD

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
        return Response(str(e), status=502)

    if resp.status_code == 401 and retry:
        log("[AUTH] SMN token expired, trying to refresh...")
        refresh_smn_token()
        return fetch_from_smn(url, retry=False)

    return resp

@app.route(f"{BASE_PATH}/<path:subpath>")
def smn_proxy(subpath):
    if not check_access_token():
        return jsonify({"error": "Unauthorized"}), 401

    if ".." in subpath or subpath.startswith("/"):
        return jsonify({"error": "Invalid path"}), 400

    url = urljoin(BASE_API + "/", subpath)

    cached = load_cache(url)
    if cached:
        log(f"[CACHE] Loaded {subpath}")
        return jsonify(cached)

    log(f"[FETCH] {url}")
    resp = fetch_from_smn(url)

    if not hasattr(resp, "status_code"):
        return Response("Upstream error", status=502)

    if resp.status_code != 200:
        return Response(resp.text, status=resp.status_code,
                        content_type=resp.headers.get("Content-Type", "text/plain"))

    try:
        data = resp.json()
        save_cache(url, data)
        return jsonify(data)
    except Exception:
        return Response("Invalid JSON from SMN", status=502)

@app.errorhandler(404)
def handle_not_found(e):
    return jsonify({
        "error": "Endpoint not found",
        "message": f"The requested URL '{request.path}' is not a valid API endpoint.",
    }), 200

@app.errorhandler(405)
def handle_method_not_allowed(e):
    return jsonify({
        "error": "Method not allowed",
        "allowed": ["GET"],
        "path": request.path
    }), 200

@app.errorhandler(Exception)
def handle_general_error(e):
    log(f"[ERROR] Unexpected exception: {e}")
    return jsonify({
        "error": "Internal error",
        "message": str(e),
        "path": request.path
    }), 200

def handle_sigint(signum, frame):
    log("shutting down gracefully...")
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

# Wrap Flask app with ASGI adapter for uvicorn
from asgiref.wsgi import WsgiToAsgi
app = WsgiToAsgi(app)