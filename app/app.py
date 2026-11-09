from flask import Flask, request, jsonify, abort, Response
from functools import wraps
import sqlite3
import os
import hashlib
import json
from html import escape
from flask import make_response


app = Flask(__name__) # NOSONAR

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Server"] = ""

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )

    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

    return response


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not Found"}), 404

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")
HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLASK_PORT", "8080"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Admin-Token", "")
        if not ADMIN_TOKEN or token != ADMIN_TOKEN:
            abort(401)
        return f(*args, **kwargs)
    return decorated

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    for u, e, p in [("alice","alice@lab.local","alice123"),
                    ("bob",  "bob@lab.local",  "bob456")]:
        h = hashlib.sha256(p.encode()).hexdigest()
        conn.execute(
            "INSERT OR IGNORE INTO users VALUES (NULL,?,?,?)", (u, e, h)
        )
    conn.commit()
    conn.close()

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

@app.route("/users", methods=["GET"])
def list_users():
    conn = sqlite3.connect(DB_PATH)
    users = conn.execute(
        "SELECT id, username, email FROM users"
    ).fetchall()
    conn.close()
    return jsonify([
        {"id": u[0], "username": u[1], "email": u[2]} for u in users
    ])

# Fix Vuln 1 : requete parametree
@app.route("/user", methods=["GET"])
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    result = conn.execute(
        "SELECT id, username, email FROM users WHERE username = ?",
        (username,)
    ).fetchall()
    conn.close()
    return jsonify([
        {"id": r[0], "username": r[1], "email": r[2]} for r in result
    ])

# Fix Vuln 2 : echappement HTML
@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    return jsonify({"query": q})

# Fix Vuln 3 + 4 : controle d'acces + pas de mot de passe en clair
@app.route("/admin/users", methods=["GET"])
@require_admin
def admin_users():
    conn = sqlite3.connect(DB_PATH)
    users = conn.execute(
        "SELECT id, username, email FROM users"
    ).fetchall()
    conn.close()
    return jsonify([
        {"id": u[0], "username": u[1], "email": u[2]} for u in users
    ])

@app.route("/admin/config", methods=["GET"])
@require_admin
def admin_config():
    return jsonify({"db_path": DB_PATH, "debug": False})

@app.route("/openapi.json", methods=["GET"])
def openapi_spec():
    from flask import Response
    import json
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "app-devsecops", "version": "1.0.0"},
        "paths": {
            "/health": {"get": {"responses": {"200": {"description": "OK"}}}},
            "/users":  {"get": {"responses": {"200": {"description": "OK"}}}},
            "/user":   {"get": {"parameters": [{"name": "username",
                        "in": "query", "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "OK"}}}},
            "/search": {"get": {"parameters": [{"name": "q",
                        "in": "query", "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "OK"}}}}
        }
    }
    return Response(json.dumps(spec), mimetype="application/json")

@app.route("/debug")
def debug():
    return dict(os.environ)   # fuite de ADMIN_TOKEN et de toutes les variables

init_db()
if __name__ == "__main__":
    app.run(host=HOST, port=PORT)
