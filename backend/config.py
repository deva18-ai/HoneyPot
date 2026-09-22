import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"
REPORT_DIR = ROOT / "reports" / "generated"
DASHBOARD_DIR = ROOT / "dashboard"
DB_PATH = DATA_DIR / "honeytrap.db"

HOST = os.getenv("HONEYTRAP_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
FTP_PORT = int(os.getenv("FTP_PORT", "2121"))
TELNET_PORT = int(os.getenv("TELNET_PORT", "2323"))
DB_PORT = int(os.getenv("DB_PORT", "9090"))

BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW = int(os.getenv("BRUTE_FORCE_WINDOW", "60"))
SCAN_SERVICE_THRESHOLD = int(os.getenv("SCAN_SERVICE_THRESHOLD", "3"))
SCAN_WINDOW = int(os.getenv("SCAN_WINDOW", "30"))

DEMO_USERS = {
    "admin": {"password": "honeytrap-admin", "role": "admin"},
    "viewer": {"password": "honeytrap-viewer", "role": "viewer"},
}

for path in (DATA_DIR, LOG_DIR, REPORT_DIR):
    path.mkdir(parents=True, exist_ok=True)
