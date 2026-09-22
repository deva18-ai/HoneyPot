from flask import Blueprint, jsonify, request, session, send_file
from .db import recent_events, recent_alerts, stats, sessions, all_events, connect
from reports.exporter import export_csv, export_pdf

api = Blueprint("api", __name__, url_prefix="/api")

def require_login():
    return session.get("user")

@api.get("/health")
def health():
    return jsonify({"status":"ok","service":"HoneyTrap"})

@api.get("/stats")
def get_stats():
    if not require_login():
        return jsonify({"error":"login required"}), 401
    return jsonify(stats())

@api.get("/events")
def get_events():
    if not require_login():
        return jsonify({"error":"login required"}), 401
    limit = min(int(request.args.get("limit",50)),200)
    return jsonify(recent_events(limit))

@api.get("/alerts")
def get_alerts():
    if not require_login():
        return jsonify({"error":"login required"}), 401
    return jsonify(recent_alerts(50))

@api.get("/sessions")
def get_sessions():
    if not require_login():
        return jsonify({"error":"login required"}), 401
    return jsonify(sessions(50))

@api.get("/export/csv")
def csv_report():
    if not require_login() or session["user"]["role"] != "admin":
        return jsonify({"error":"admin role required"}), 403
    path = export_csv(all_events())
    return send_file(path, as_attachment=True)

@api.get("/export/pdf")
def pdf_report():
    if not require_login() or session["user"]["role"] != "admin":
        return jsonify({"error":"admin role required"}), 403
    path = export_pdf(all_events(), stats())
    return send_file(path, as_attachment=True)
