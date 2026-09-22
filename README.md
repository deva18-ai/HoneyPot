# HoneyTrap v2.0
## Advanced Honeypot Intrusion Detection & SOC Platform

HoneyTrap is a defensive, local-only honeypot system that exposes fake services, records attacker activity, classifies threats using MITRE ATT&CK framework, calculates threat scores, and provides a professional SOC-grade dashboard for incident investigation.

### ⚠️ Safety
Run HoneyTrap only on a private/isolated lab network or VM. Do not expose it to the public Internet without explicit approval. Use only synthetic credentials and test only systems you own or are authorized to test.

---

## 🚀 Features

### Honeypot Services
- **SSH** (port 2222) - Full SSH banner, auth emulation
- **FTP** (port 2121) - FTP auth sequence
- **Telnet** (port 2323) - Telnet login emulation
- **Database** (port 9090) - PostgreSQL banner probe
- **HTTP Honeypot** (port 8081) - Web admin panels, WP login, phpMyAdmin, .env traps

### Detection & Classification
- **10 Attack Categories**: Brute Force, Credential Stuffing, Port Scan, Service Scan, Web Recon, Exploit Attempt, Credential Abuse, Lateral Movement, Data Exfil, C2
- **Weighted Threat Scoring** (0-100): Velocity, reputation, target sensitivity, success rate, honeytoken triggers, MITRE severity
- **MITRE ATT&CK Mapping**: 46+ techniques across 14 tactics
- **Behavioral Analysis**: Event sequencing, stage detection (Initial Access → Execution → Persistence → etc.)
- **Anomaly Detection**: Statistical spike detection, baseline profiling

### Incident Management
- **Auto-correlation**: Groups related events by IP + time window
- **Investigation View**: Timeline, behavior tree, evidence, MITRE panel
- **Evidence Packaging**: Payloads, transcripts, hash-chain verification
- **Notes & Tagging**: Collaboration, campaign linking
- **Status Workflow**: Open → In Progress → Acknowledged → Resolved/Closed

### SOC Dashboard (React + TypeScript + Tailwind)
- **Threat Overview**: KPI cards, attack trends, distribution, top attackers, service heatmap
- **Incidents**: Filterable, sortable, paginated with bulk actions
- **Events**: Real-time feed with WebSocket, advanced filtering
- **Investigation**: Timeline visualization, behavior tree, evidence, MITRE details
- **IP Analysis**: Geo/ASN enrichment, reputation, event history, block/unblock
- **Services**: Health monitoring, configuration, banner customization
- **Alerts**: Real-time, acknowledgment, bulk operations
- **MITRE ATT&CK**: Matrix view, technique details, coverage reporting
- **Reports**: CSV/JSON export, scheduled generation
- **Settings**: Profile, security (password/API keys), notifications, service config, detection tuning

### Architecture
```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  ATTACKER   │────▶│  HONEYPOT LAYER  │────▶│ EVENT COLLECTOR │
└─────────────┘     │ SSH │ FTP │ HTTP │     └────────┬────────┘
                    │ Telnet │ DB   │                  │
                    └──────────────────┘                  ▼
                                              ┌──────────────────┐
                                              │ DETECTION PIPELINE│
                                              │ Enrich → Classify │
                                              │ → Score → Map →   │
                                              │ Alert → Persist   │
                                              └────────┬─────────┘
                                                       ▼
                                              ┌──────────────────┐
                                              │  INCIDENT MGR    │
                                              │ Correlate → Build │
                                              │ → Evidence → MITRE│
                                              └────────┬─────────┘
                                                       ▼
                                              ┌──────────────────┐
                                              │   SOC DASHBOARD  │
                                              │ React + TS + WS  │
                                              └──────────────────┘
```

---

## 📦 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ (for dashboard)
- Redis (optional, for caching/queue)

### Backend Setup
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings (SECRET_KEY required for production!)

# Initialize database (runs migrations)
alembic upgrade head

# Seed MITRE ATT&CK techniques
python -m backend.scripts.seed_mitre

# Start backend
python -m backend.main
```

### Dashboard Setup
```bash
cd dashboard
npm install
npm run dev  # Development with hot reload
# OR
npm run build  # Production build (outputs to backend/dashboard)
```

### Docker (Production)
```bash
docker-compose up -d --build
```

---

## 🔧 Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing key (REQUIRED in production) | - |
| `DATABASE_URL` | SQLAlchemy async connection string | `sqlite+aiosqlite:///./data/honeytrap.db` |
| `REDIS_URL` | Redis for caching/queue | `redis://localhost:6379/0` |
| `BRUTE_FORCE_THRESHOLD` | Failed logins before alert | 5 |
| `SCAN_SERVICE_THRESHOLD` | Services hit before scan alert | 3 |
| `TELEGRAM_BOT_TOKEN` | Bot token for alerts | - |
| `SMTP_HOST` | Email server for alerts | - |

---

## 📡 API Endpoints

### Authentication
- `POST /api/v1/auth/login` - Login (form data)
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Revoke refresh token
- `GET /api/v1/auth/me` - Current user info

### Dashboard
- `GET /api/v1/dashboard/stats` - Dashboard KPIs
- `GET /api/v1/dashboard/threat-overview` - Threat overview data

### Events
- `GET /api/v1/events` - Paginated events (filterable)
- `GET /api/v1/events/{id}` - Single event
- `GET /api/v1/events/stats/summary` - Event statistics
- `GET /api/v1/events/stats/trend` - Time-series trend

### Incidents
- `GET /api/v1/incidents` - Paginated incidents (filterable)
- `GET /api/v1/incidents/{id}` - Full incident with relations
- `GET /api/v1/incidents/{id}/timeline` - Event timeline
- `GET /api/v1/incidents/{id}/evidence` - Evidence list
- `GET /api/v1/incidents/{id}/mitre` - MITRE technique details
- `PATCH /api/v1/incidents/{id}` - Update incident
- `POST /api/v1/incidents/{id}/notes` - Add note
- `POST /api/v1/incidents/{id}/evidence` - Add evidence

### IP Analysis
- `GET /api/v1/ip-stats` - Paginated IP statistics
- `GET /api/v1/ip-stats/{ip}` - IP details
- `GET /api/v1/ip-stats/{ip}/events` - IP event history
- `POST /api/v1/ip-stats/{ip}/block` - Block IP
- `POST /api/v1/ip-stats/{ip}/unblock` - Unblock IP

### Alerts
- `GET /api/v1/alerts` - Paginated alerts
- `GET /api/v1/alerts/stats/summary` - Alert statistics
- `PATCH /api/v1/alerts/{id}/acknowledge` - Acknowledge
- `POST /api/v1/alerts/bulk-acknowledge` - Bulk acknowledge

### MITRE ATT&CK
- `GET /api/v1/mitre` - Paginated techniques
- `GET /api/v1/mitre/tactics` - Tactic list with counts
- `GET /api/v1/mitre/matrix` - Full matrix
- `GET /api/v1/mitre/coverage` - Detection coverage

### Reports
- `GET /api/v1/reports/export/csv` - Events CSV
- `GET /api/v1/reports/export/incidents/csv` - Incidents CSV
- `GET /api/v1/reports/export/json` - Events JSON
- `GET /api/v1/reports/list` - Generated reports

### WebSocket
- `WS /ws/events` - Real-time events
- `WS /ws/alerts` - Real-time alerts

---

## 🧪 Testing

```bash
# Backend tests
pytest tests/ -v --cov=backend

# Dashboard tests
cd dashboard && npm test
```

---

## 📁 Project Structure

```
HoneyTrap/
├── backend/
│   ├── api/v1/           # FastAPI routes (auth, events, incidents, etc.)
│   ├── core/             # Config, security, lifespan
│   ├── db/               # Database session, models
│   ├── models/           # SQLAlchemy models
│   ├── schemas/          # Pydantic schemas
│   ├── services/         # Business logic (incident_manager, honeypot_manager)
│   ├── scripts/          # Seed scripts, maintenance
│   └── main.py           # FastAPI app entry point
├── dashboard/
│   ├── src/
│   │   ├── components/   # React components (layout, UI)
│   │   ├── pages/        # Page components
│   │   ├── context/      # React context (Auth, WebSocket)
│   │   ├── services/     # API client
│   │   ├── hooks/        # Custom hooks
│   │   ├── types/        # TypeScript types
│   │   └── utils/        # Helpers
│   └── package.json
├── detector/
│   ├── pipeline.py       # Detection pipeline stages
│   ├── classifiers/      # Attack classification
│   ├── scoring/          # Threat scoring
│   └── intelligence/     # MITRE mapping, threat intel
├── honeypots/            # Socket service handlers
├── alembic/              # Database migrations
├── tests/                # Pytest tests
├── requirements.txt      # Python dependencies
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

## 🔐 Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | honeytrap-admin | admin |
| viewer | honeytrap-viewer | viewer |

**Change these immediately in production!**

---

## 🛡️ Security Notes

- All passwords hashed with Argon2id
- JWT tokens with short expiry + refresh rotation
- SQLite WAL mode + hash-chain for tamper-evident logs
- No external connections without explicit configuration
- CSP headers, HSTS, secure cookies in production

---

## 📄 License

Educational/Research use only. Not for production deployment without security review.

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Run tests: `pytest` and `npm test`
4. Submit PR with description

---

## 📞 Support

For issues, check:
- `alembic upgrade head` for database
- `docker-compose logs` for container issues
- Browser console for dashboard errors
- Backend logs at `logs/honeytrap.log`