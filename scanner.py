"""
Vulnerability Scanner + PDF Report Generator
Educational penetration testing tool.
Only scan systems you own or have written permission to test.
"""

import socket
import concurrent.futures
import requests
import datetime
import sys
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import mm

# ── Port + service map ────────────────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB"
}

# ── Vulnerability checks ──────────────────────────────────────────────────────
VULN_CHECKS = {
    21:  {"name": "FTP Anonymous Login",     "severity": "HIGH",   "test": "anon_ftp",   "remediation": "Disable anonymous FTP access. Require authenticated users only."},
    22:  {"name": "SSH Outdated Banner",     "severity": "MEDIUM", "test": "ssh_banner",  "remediation": "Update OpenSSH to latest version. Disable root login."},
    23:  {"name": "Telnet Enabled",          "severity": "CRITICAL","test": "telnet_open","remediation": "Disable Telnet immediately. Use SSH instead — all Telnet traffic is unencrypted."},
    80:  {"name": "HTTP (No TLS)",           "severity": "MEDIUM", "test": "http_open",   "remediation": "Redirect all HTTP traffic to HTTPS. Implement HSTS."},
    3306:{"name": "MySQL Exposed",           "severity": "HIGH",   "test": "port_open",   "remediation": "Bind MySQL to localhost only. Never expose port 3306 externally."},
    3389:{"name": "RDP Exposed",             "severity": "HIGH",   "test": "port_open",   "remediation": "Restrict RDP to VPN only. Enable Network Level Authentication."},
    6379:{"name": "Redis No Auth",           "severity": "CRITICAL","test": "redis_auth",  "remediation": "Set a Redis password. Bind to localhost. Never expose Redis publicly."},
    445: {"name": "SMB Exposed",             "severity": "HIGH",   "test": "port_open",   "remediation": "Block SMB at the firewall. Apply all MS17-010 patches (EternalBlue)."},
    27017:{"name": "MongoDB Exposed",        "severity": "CRITICAL","test": "port_open",   "remediation": "Enable MongoDB authentication. Bind to localhost only."},
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": colors.HexColor("#c0392b"),
    "HIGH":     colors.HexColor("#e67e22"),
    "MEDIUM":   colors.HexColor("#f1c40f"),
    "LOW":      colors.HexColor("#27ae60"),
    "INFO":     colors.HexColor("#2980b9"),
}

# ── Scanner ───────────────────────────────────────────────────────────────────
def scan_port(host, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return port if result == 0 else None
    except Exception:
        return None

def grab_banner(host, port, timeout=2.0):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner[:200] if banner else None
    except Exception:
        return None

def check_anon_ftp(host):
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(host, 21, timeout=3)
        ftp.login("anonymous", "anon@anon.com")
        ftp.quit()
        return True
    except Exception:
        return False

def check_redis_auth(host):
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect((host, 6379))
        s.send(b"PING\r\n")
        resp = s.recv(64).decode(errors="ignore")
        s.close()
        return "+PONG" in resp   # No auth required
    except Exception:
        return False

def run_vuln_checks(host, open_ports):
    findings = []
    for port in open_ports:
        service = COMMON_PORTS.get(port, f"Port {port}")
        banner  = grab_banner(host, port)

        if port not in VULN_CHECKS:
            findings.append({
                "port": port, "service": service,
                "name": f"Open Port — {service}",
                "severity": "INFO",
                "detail": banner or "Port is open and accepting connections.",
                "remediation": "Review whether this service needs to be publicly accessible."
            })
            continue

        check = VULN_CHECKS[port]
        vuln_found = False
        detail = banner or "Service is running and port is open."

        if check["test"] == "anon_ftp":
            vuln_found = check_anon_ftp(host)
            detail = "Anonymous FTP login succeeded — no credentials required." if vuln_found else "Anonymous login blocked."
        elif check["test"] == "redis_auth":
            vuln_found = check_redis_auth(host)
            detail = "Redis responded to PING without authentication." if vuln_found else "Redis appears to require authentication."
        elif check["test"] == "telnet_open":
            vuln_found = True
            detail = f"Telnet service detected. Banner: {banner}" if banner else "Telnet port is open — all traffic transmitted in plaintext."
        elif check["test"] == "http_open":
            vuln_found = True
            detail = "HTTP service running without TLS encryption."
        elif check["test"] == "ssh_banner":
            if banner:
                vuln_found = any(old in banner for old in ["OpenSSH_6", "OpenSSH_5", "OpenSSH_4"])
                detail = f"Banner: {banner}"
            else:
                vuln_found = False
        elif check["test"] == "port_open":
            vuln_found = True
            detail = f"Service exposed on public interface. Banner: {banner}" if banner else "Service is externally accessible."

        if vuln_found:
            findings.append({
                "port": port, "service": service,
                "name": check["name"],
                "severity": check["severity"],
                "detail": detail,
                "remediation": check["remediation"]
            })

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return findings

# ── PDF Report ────────────────────────────────────────────────────────────────
def generate_report(host, open_ports, findings, filename):
    doc   = SimpleDocTemplate(filename, pagesize=A4,
                               leftMargin=20*mm, rightMargin=20*mm,
                               topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # Title block
    story.append(Paragraph("PENETRATION TEST REPORT", ParagraphStyle(
        "title", fontSize=24, textColor=colors.HexColor("#2c3e50"),
        spaceAfter=4, fontName="Helvetica-Bold")))
    story.append(Paragraph("Automated Vulnerability Assessment", ParagraphStyle(
        "sub", fontSize=12, textColor=colors.HexColor("#7f8c8d"), spaceAfter=2)))
    story.append(Spacer(1, 6*mm))

    # Meta table
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = {s: sum(1 for f in findings if f["severity"]==s)
              for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
    meta = [
        ["Target", host,         "Date",     now],
        ["Open Ports", str(len(open_ports)), "Total Findings", str(len(findings))],
        ["Critical", str(counts["CRITICAL"]), "High", str(counts["HIGH"])],
        ["Medium",   str(counts["MEDIUM"]),   "Info", str(counts["INFO"])],
    ]
    t = Table(meta, colWidths=[40*mm, 60*mm, 40*mm, 60*mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#f8f9fa")),
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#2c3e50")),
        ("BACKGROUND", (2,0), (2,-1), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",  (0,0), (0,-1), colors.white),
        ("TEXTCOLOR",  (2,0), (2,-1), colors.white),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("PADDING",    (0,0), (-1,-1), 6),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#dee2e6")),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story.append(t)
    story.append(Spacer(1, 8*mm))

    # Executive summary
    story.append(Paragraph("Executive Summary", ParagraphStyle(
        "h2", fontSize=14, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#2c3e50"), spaceBefore=4, spaceAfter=4)))
    crit = counts["CRITICAL"] + counts["HIGH"]
    summary = (f"A vulnerability assessment was conducted against <b>{host}</b> on {now}. "
               f"The scan identified <b>{len(open_ports)} open ports</b> and "
               f"<b>{len(findings)} security findings</b>, of which "
               f"<b>{crit} are rated Critical or High severity</b> and require immediate attention. "
               f"Detailed findings and remediation guidance are provided below.")
    story.append(Paragraph(summary, styles["Normal"]))
    story.append(Spacer(1, 6*mm))

    # Open ports table
    story.append(Paragraph("Open Ports", ParagraphStyle(
        "h2", fontSize=14, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#2c3e50"), spaceBefore=4, spaceAfter=4)))
    port_data = [["Port", "Service", "Status"]]
    for p in sorted(open_ports):
        port_data.append([str(p), COMMON_PORTS.get(p, "Unknown"), "OPEN"])
    pt = Table(port_data, colWidths=[30*mm, 80*mm, 40*mm])
    pt.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0),  colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",   (0,0), (-1,0),  colors.white),
        ("FONTNAME",    (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTNAME",    (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",    (0,0), (-1,-1), 9),
        ("PADDING",     (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#dee2e6")),
    ]))
    story.append(pt)
    story.append(Spacer(1, 8*mm))

    # Findings
    story.append(Paragraph("Detailed Findings", ParagraphStyle(
        "h2", fontSize=14, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#2c3e50"), spaceBefore=4, spaceAfter=4)))

    for i, f in enumerate(findings, 1):
        sev_color = SEVERITY_COLOR.get(f["severity"], colors.gray)
        header = [[
            Paragraph(f"<b>FINDING {i:02d}</b>", ParagraphStyle("fh", fontSize=9, textColor=colors.white)),
            Paragraph(f["severity"], ParagraphStyle("sev", fontSize=9, textColor=colors.white, alignment=2)),
        ]]
        ht = Table(header, colWidths=[130*mm, 30*mm])
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), sev_color),
            ("PADDING",    (0,0), (-1,-1), 6),
        ]))
        story.append(ht)

        body = [
            ["Finding",      f["name"]],
            ["Port/Service", f"{f['port']} / {f['service']}"],
            ["Detail",       f["detail"]],
            ["Remediation",  f["remediation"]],
        ]
        bt = Table(body, colWidths=[35*mm, 125*mm])
        bt.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (0,-1), colors.HexColor("#f8f9fa")),
            ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME",    (1,0), (1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0), (-1,-1), 9),
            ("PADDING",     (0,0), (-1,-1), 6),
            ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#dee2e6")),
            ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ]))
        story.append(bt)
        story.append(Spacer(1, 4*mm))

    # Footer
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(
        "This report was generated automatically for educational purposes. "
        "Only use against systems you own or have explicit written permission to test.",
        ParagraphStyle("footer", fontSize=8, textColor=colors.HexColor("#95a5a6"))))

    doc.build(story)
    print(f"[+] Report saved: {filename}")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    target = input("Enter target IP: ").strip()

    try:
        socket.inet_aton(target)
    except socket.error:
        try:
            target = socket.gethostbyname(target)
            print(f"[*] Resolved to {target}")
        except Exception:
            print("[!] Invalid target"); sys.exit(1)

    print(f"\n[*] Scanning {target} ...")
    ports = list(COMMON_PORTS.keys())

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(lambda p: scan_port(target, p), ports))

    open_ports = [p for p in results if p]
    print(f"[+] Open ports: {open_ports}")

    print("[*] Running vulnerability checks ...")
    findings = run_vuln_checks(target, open_ports)

    print(f"[+] Found {len(findings)} issues\n")
    for f in findings:
        print(f"  [{f['severity']:8}] {f['name']} (port {f['port']})")

    fname = f"report_{target.replace('.','_')}_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    generate_report(target, open_ports, findings, fname)
    print(f"\n[*] Done. Open {fname} to view the report.")

if __name__ == "__main__":
    main()
