import secrets

from flask import Flask, jsonify, redirect, request, session

from honeypots.socket_services import start_socket_services

from .api import api
from .config import DASHBOARD_DIR, DEMO_USERS, HOST, WEB_PORT
from .db import init_db
from .logger import log_event

app = Flask(__name__, static_folder=None)
app.secret_key = secrets.token_hex(32)
app.register_blueprint(api)


def current_user():
    return session.get("user")


@app.get("/")
def index():
    if not current_user():
        return redirect("/login")
    return (DASHBOARD_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/login")
def login_page():
    return (DASHBOARD_DIR / "login.html").read_text(encoding="utf-8")


@app.post("/login")
def login():
    data = request.get_json(silent=True) or request.form
    username = data.get("username", "")
    password = data.get("password", "")
    user = DEMO_USERS.get(username)
    if user and secrets.compare_digest(password, user["password"]):
        session["user"] = {"username": username, "role": user["role"]}
        log_event(
            request.remote_addr or "127.0.0.1",
            "HTTP",
            "AUTH_ATTEMPT",
            username=username,
            password=password,
            result="SUCCESS",
            request_path="/login",
            payload="dashboard login",
        )
        return jsonify({"ok": True, "role": user["role"]})
    log_event(
        request.remote_addr or "127.0.0.1",
        "HTTP",
        "AUTH_ATTEMPT",
        username=username,
        password=password,
        result="FAIL",
        request_path="/login",
        payload="dashboard login",
    )
    return jsonify({"ok": False, "error": "invalid demo credentials"}), 401


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/me")
def me():
    user = current_user()
    return jsonify(user or {"logged_in": False})


@app.get("/decoy/files")
def decoy_files():
    # Synthetic files only. Opening a decoy file is logged.
    ip = request.remote_addr or "127.0.0.1"
    name = request.args.get("name", "readme.txt")
    allowed = {
        "readme.txt": "HoneyTrap synthetic document.",
        "aws_credentials.txt": "ACCESS_KEY=HT-DEMO-API-7F3A-LOCAL",
        "database_backup.sql": "DECOY_DB_PASSWORD=HT-DECOY-PASS-92B1",
    }
    if name not in allowed:
        log_event(
            ip,
            "HTTP",
            "PATH_REQUEST",
            request_path="/decoy/files",
            payload=name,
            result="FAIL",
        )
        return "Not found", 404
    log_event(
        ip,
        "FILE_STORE",
        "FILE_OPEN",
        request_path=name,
        payload=allowed[name],
        result="SUCCESS",
    )
    return f"<pre>{allowed[name]}</pre>"


def main():
    init_db()
    start_socket_services()
    app.run(host=HOST, port=WEB_PORT, debug=False, threaded=True)


if __name__ == "__main__":
    main()
