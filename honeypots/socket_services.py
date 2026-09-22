import socket
import threading
from backend.config import HOST, SSH_PORT, FTP_PORT, TELNET_PORT, DB_PORT
from backend.logger import log_event
from detector.engine import country_for_ip, fingerprint_for

def _serve(port, service, banner, handler):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(20)
    print(f"[HoneyTrap] {service} listening on {HOST}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(
            target=handler, args=(conn,addr), daemon=True
        ).start()

def _session(service, ip):
    with __import__("backend.db", fromlist=["connect"]).connect() as db:
        cur = db.execute(
            "INSERT INTO sessions(source_ip,service,started_at) VALUES(?,?,?)",
            (ip,service,__import__("backend.db",fromlist=["utc_now"]).utc_now())
        )
        db.commit()
        return cur.lastrowid

def ssh_handler(conn, addr):
    ip = addr[0]
    sid = _session("SSH",ip)
    try:
        conn.sendall(b"SSH-2.0-OpenSSH_8.9-HoneyTrap\r\nlogin: ")
        username = conn.recv(256).decode("utf-8","ignore").strip()
        conn.sendall(b"password: ")
        password = conn.recv(256).decode("utf-8","ignore").strip()
        fp = fingerprint_for("SSH", username, "")
        log_event(ip,"SSH","AUTH_ATTEMPT",username,password,
                  result="FAIL",session_id=sid,fingerprint=fp,country=country_for_ip(ip))
        conn.sendall(b"Access denied. This is a defensive honeypot.\r\n")
    except Exception as exc:
        log_event(ip,"SSH","CONNECTION",payload=str(exc),result="FAIL",session_id=sid)
    finally:
        conn.close()

def ftp_handler(conn, addr):
    ip = addr[0]
    sid = _session("FTP",ip)
    try:
        conn.sendall(b"220 HoneyTrap FTP Service\r\nUsername: ")
        username = conn.recv(256).decode("utf-8","ignore").strip()
        conn.sendall(b"Password: ")
        password = conn.recv(256).decode("utf-8","ignore").strip()
        log_event(ip,"FTP","AUTH_ATTEMPT",username,password,
                  result="FAIL",session_id=sid,country=country_for_ip(ip))
        conn.sendall(b"530 Login incorrect\r\n")
    except Exception as exc:
        log_event(ip,"FTP","CONNECTION",payload=str(exc),result="FAIL",session_id=sid)
    finally:
        conn.close()

def telnet_handler(conn, addr):
    ip = addr[0]
    sid = _session("TELNET",ip)
    try:
        conn.sendall(b"Welcome to HoneyTrap Telnet\r\nlogin: ")
        username = conn.recv(256).decode("utf-8","ignore").strip()
        conn.sendall(b"Password: ")
        password = conn.recv(256).decode("utf-8","ignore").strip()
        log_event(ip,"TELNET","AUTH_ATTEMPT",username,password,
                  result="FAIL",session_id=sid,country=country_for_ip(ip))
        conn.sendall(b"Login failed.\r\n")
    except Exception as exc:
        log_event(ip,"TELNET","CONNECTION",payload=str(exc),result="FAIL",session_id=sid)
    finally:
        conn.close()

def db_handler(conn, addr):
    ip = addr[0]
    sid = _session("DB",ip)
    try:
        conn.sendall(b"PostgreSQL 15.2 HoneyTrap Database\r\n")
        data = conn.recv(512).decode("utf-8","ignore").strip()
        log_event(ip,"DB","BANNER_PROBE",payload=data,result="SUCCESS",
                  session_id=sid,country=country_for_ip(ip))
        conn.sendall(b"ERROR: synthetic database endpoint; no real database is exposed.\r\n")
    except Exception as exc:
        log_event(ip,"DB","CONNECTION",payload=str(exc),result="FAIL",session_id=sid)
    finally:
        conn.close()

def start_socket_services():
    services = [
        (SSH_PORT,"SSH","",ssh_handler),
        (FTP_PORT,"FTP","",ftp_handler),
        (TELNET_PORT,"TELNET","",telnet_handler),
        (DB_PORT,"DB","",db_handler),
    ]
    for args in services:
        threading.Thread(target=_serve,args=args,daemon=True).start()
