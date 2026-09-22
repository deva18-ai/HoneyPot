import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.session import async_session_maker
from backend.models import MitreTechnique


MITRE_TECHNIQUES = [
    # Reconnaissance
    ("T1590.001", "Active Scanning: Scan IP Blocks", "Reconnaissance", "Network", "Detect unexpected inbound connections from unknown IPs", "Network segmentation, firewall rules"),
    ("T1590.005", "Active Scanning: Vulnerability Scanning", "Reconnaissance", "Network", "Monitor for vulnerability scanner signatures", "Patch management, WAF"),
    ("T1595.001", "Active Scanning: Port Scanning", "Reconnaissance", "Network", "Detect rapid port connection attempts", "Port knocking, fail2ban"),
    
    # Resource Development
    ("T1588.002", "Obtain Capabilities: Tool", "Resource Development", "Multi-platform", "Monitor for known tool signatures", "Application allowlisting"),
    
    # Initial Access
    ("T1190", "Exploit Public-Facing Application", "Initial Access", "Multi-platform", "WAF alerts, unusual HTTP requests", "Patch management, WAF"),
    ("T1133", "External Remote Services", "Initial Access", "Multi-platform", "Monitor VPN/RDP/SSH access", "MFA, zero trust"),
    ("T1110.001", "Brute Force: Password Guessing", "Initial Access", "Multi-platform", "Failed login monitoring, rate limiting", "Account lockout, MFA"),
    ("T1110.003", "Brute Force: Password Spraying", "Initial Access", "Multi-platform", "Single password across multiple accounts", "Account lockout, MFA"),
    ("T1110.004", "Brute Force: Credential Stuffing", "Initial Access", "Multi-platform", "Known breached credentials usage", "Breach monitoring, MFA"),
    
    # Execution
    ("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution", "Windows", "PowerShell logging, script block logging", "Constrained language mode"),
    ("T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", "Linux/macOS", "Shell history, auditd", "Restricted shells"),
    ("T1059.006", "Command and Scripting Interpreter: Python", "Execution", "Multi-platform", "Python execution monitoring", "Application allowlisting"),
    ("T1204", "User Execution", "Execution", "Multi-platform", "Phishing link/file execution", "User training, email filtering"),
    
    # Persistence
    ("T1505.003", "Server Software Component: Web Shell", "Persistence", "Web Server", "File integrity monitoring, unusual web files", "WAF, file monitoring"),
    ("T1505.004", "Server Software Component: IIS Components", "Persistence", "Windows", "IIS module monitoring", "IIS hardening"),
    ("T1098", "Account Manipulation", "Persistence", "Multi-platform", "Account creation/modification alerts", "Privileged access management"),
    
    # Privilege Escalation
    ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "Multi-platform", "Unusual process behavior, CVE exploits", "Patch management"),
    ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation", "Linux/macOS", "Sudo log monitoring", "Sudoers hardening"),
    
    # Defense Evasion
    ("T1070.004", "Indicator Removal: File Deletion", "Defense Evasion", "Multi-platform", "File deletion monitoring", "Audit logging"),
    ("T1222.002", "File and Directory Permissions Modification: Linux and Mac File and Directory Permissions Modification", "Defense Evasion", "Linux/macOS", "chmod/chown monitoring", "File integrity monitoring"),
    ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion", "Multi-platform", "Antivirus/EDR tampering alerts", "Tamper protection"),
    
    # Credential Access
    ("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access", "Windows", "LSASS access monitoring", "Credential guard"),
    ("T1555.003", "Credentials from Password Managers", "Credential Access", "Multi-platform", "Browser/manager access monitoring", "Hardware tokens"),
    ("T1556.002", "Modify Authentication Process: Password Filter", "Credential Access", "Windows", "Password filter DLL monitoring", "Code signing"),
    
    # Discovery
    ("T1082", "System Information Discovery", "Discovery", "Multi-platform", "System info queries", "Least privilege"),
    ("T1083", "File and Directory Discovery", "Discovery", "Multi-platform", "Directory enumeration", "Least privilege"),
    ("T1018", "Remote System Discovery", "Discovery", "Multi-platform", "Network scanning detection", "Network segmentation"),
    ("T1069.002", "Permission Groups Discovery: Permission Groups Discovery", "Discovery", "Multi-platform", "Group enumeration", "Least privilege"),
    ("T1057", "Process Discovery", "Discovery", "Multi-platform", "Process listing", "Process hiding"),
    
    # Lateral Movement
    ("T1021.004", "Remote Services: Pass the Hash", "Lateral Movement", "Windows", "Pass-the-hash detection", "Credential guard, RDP restriction"),
    ("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement", "Windows", "RDP connection monitoring", "MFA, network level auth"),
    ("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement", "Windows", "SMB admin share access", "Disable admin shares"),
    ("T1550.002", "Use Alternate Authentication Material: Pass the Hash", "Lateral Movement", "Windows", "Kerberos/NTLM anomalies", "Credential guard"),
    
    # Collection
    ("T1005", "Data from Local System", "Collection", "Multi-platform", "Large file reads, archive creation", "DLP, encryption"),
    ("T1056.001", "Input Capture: Keylogging", "Collection", "Multi-platform", "Keyboard hook detection", "Anti-keylogger"),
    ("T1115", "Clipboard Data", "Collection", "Multi-platform", "Clipboard access monitoring", "Clipboard restrictions"),
    
    # Command and Control
    ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "Multi-platform", "HTTP/HTTPS beaconing detection", "Proxy inspection"),
    ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "Multi-platform", "DNS tunneling detection", "DNS monitoring"),
    ("T1105", "Ingress Tool Transfer", "Command and Control", "Multi-platform", "File download from suspicious sources", "Application allowlisting"),
    ("T1573.001", "Encrypted Channel: Symmetric Cryptography", "Command and Control", "Multi-platform", "Encrypted traffic analysis", "TLS inspection"),
    
    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "Multi-platform", "Large outbound transfers", "DLP, egress filtering"),
    ("T1048.003", "Exfiltration Over Alternative Protocol: Unencrypted/Obfuscated", "Exfiltration", "Multi-platform", "Non-standard protocol transfers", "Protocol allowlisting"),
    ("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration", "Multi-platform", "Cloud storage uploads", "CASB, DLP"),
    
    # Impact
    ("T1486", "Data Encrypted for Impact", "Impact", "Multi-platform", "Rapid file encryption", "Backups, EDR"),
    ("T1490", "Inhibit System Recovery", "Impact", "Multi-platform", "Backup deletion, shadow copy removal", "Immutable backups"),
    ("T1499.001", "Endpoint Denial of Service: OS Exhaustion", "Impact", "Multi-platform", "Resource exhaustion", "Resource limits"),
]


async def seed_mitre_techniques():
    async with async_session_maker() as db:
        for tech_id, name, tactic, platform, detection, mitigation in MITRE_TECHNIQUES:
            existing = await db.execute(
                select(MitreTechnique).where(MitreTechnique.technique_id == tech_id)
            )
            if existing.scalar_one_or_none():
                continue
            
            technique = MitreTechnique(
                technique_id=tech_id,
                name=name,
                description=f"{name} - {tactic} tactic technique",
                tactic=tactic,
                platform=platform,
                detection=detection,
                mitigation=mitigation,
                is_subtechnique="." in tech_id,
                parent_technique=tech_id.split(".")[0] if "." in tech_id else None,
            )
            db.add(technique)
        
        await db.commit()
        print(f"Seeded {len(MITRE_TECHNIQUES)} MITRE ATT&CK techniques")


if __name__ == "__main__":
    asyncio.run(seed_mitre_techniques())