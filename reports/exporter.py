import csv
from pathlib import Path
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from backend.config import REPORT_DIR

def export_csv(events):
    path = REPORT_DIR / "honeytrap_events.csv"
    fields = ["id","timestamp","source_ip","service","event_type","username",
              "request_path","result","severity","threat_score","fingerprint","country"]
    with open(path,"w",newline="",encoding="utf-8") as f:
        w = csv.DictWriter(f,fieldnames=fields)
        w.writeheader()
        for e in events:
            w.writerow({k:e.get(k,"") for k in fields})
    return path

def export_pdf(events, stats):
    path = REPORT_DIR / "honeytrap_report.pdf"
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path),pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36)
    story = [
        Paragraph("HoneyTrap Security Monitoring Report", styles["Title"]),
        Paragraph("Defensive local honeypot demonstration", styles["Normal"]),
        Spacer(1,12),
        Paragraph(
            f"Total events: {stats['total_events']} | High severity: {stats['high_severity']} | "
            f"Alerts: {stats['alerts']} | Unique IPs: {stats['unique_ips']}",
            styles["Normal"]
        ),
        Spacer(1,12)
    ]
    rows = [["Time","IP","Service","Event","Severity","Score"]]
    for e in events[-50:]:
        rows.append([
            str(e.get("timestamp",""))[:19], e.get("source_ip",""),
            e.get("service",""), e.get("event_type","")[:28],
            e.get("severity",""), str(e.get("threat_score",""))
        ])
    t = Table(rows, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.lightgrey),
        ("GRID",(0,0),(-1,-1),0.25,colors.grey),
        ("FONTSIZE",(0,0),(-1,-1),7),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1,12))
    story.append(Paragraph(
        "Safety note: this report is intended for activity generated against the student's own isolated honeypot.",
        styles["Italic"]
    ))
    doc.build(story)
    return path
