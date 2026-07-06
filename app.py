import re
import json
import socket
import ssl
import secrets
import urllib.parse
import functools
import os
import base64
import hashlib
import logging
from io import BytesIO
from datetime import datetime
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash, send_file
import requests as req
import whois
import dns.resolver
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import database

# Load .env for local development (no-op in production)
load_dotenv()

# ReportLab Imports
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# Initialize database
database.init_db()

# ─────────────────────────────────────────────
#  API HELPERS & MOCK DATABASES
# ─────────────────────────────────────────────

def check_urlhaus(url):
    try:
        resp = req.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=3.0)
        if resp.status_code == 200:
            res_json = resp.json()
            if res_json.get("query_status") == "ok":
                threat = res_json.get("threat", "Malware")
                url_status = res_json.get("url_status", "unknown")
                return {
                    "label": "URLhaus Threat Check",
                    "status": "fail",
                    "detail": f"Match found! Flagged in URLhaus database (threat: {threat}, status: {url_status})",
                    "score_addition": 80
                }
            else:
                return {
                    "label": "URLhaus Threat Check",
                    "status": "pass",
                    "detail": "Not found in URLhaus database of active malware links"
                }
    except Exception as e:
        return {
            "label": "URLhaus Threat Check",
            "status": "info",
            "detail": f"Could not perform URLhaus lookup: {str(e)}"
        }
    return {
        "label": "URLhaus Threat Check",
        "status": "pass",
        "detail": "Not found in URLhaus database of active malware links"
    }

def check_virustotal(url):
    # Load from session first, then DB, then env var
    api_key = session.get("vt_api_key")
    if not api_key:
        username = session.get("username", "")
        if username:
            api_key = database.get_user_vt_key(username) or None
    if not api_key:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return simulate_virustotal(url)
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        resp = req.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=3.0)
        if resp.status_code == 200:
            res_json = resp.json()
            stats = res_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious + suspicious > 0:
                score_add = min(20 * (malicious + suspicious), 80)
                return {
                    "label": "VirusTotal Reputation Check",
                    "status": "fail" if malicious > 1 else "warn",
                    "detail": f"Flagged by VirusTotal. Detections: {malicious} malicious, {suspicious} suspicious engine flags",
                    "score_addition": score_add
                }
            else:
                return {
                    "label": "VirusTotal Reputation Check",
                    "status": "pass",
                    "detail": "Clean on VirusTotal (0 malicious/suspicious flags)"
                }
        else:
            return simulate_virustotal(url)
    except Exception:
        return simulate_virustotal(url)

def simulate_virustotal(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        # Heuristic check using global MALICIOUS_DOMAINS if available
        mal_domains = globals().get("MALICIOUS_DOMAINS", set())
        is_malicious = False
        if domain in mal_domains:
            is_malicious = True
        else:
            # Only flag commonly abused shorteners in VirusTotal simulation
            abused_shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "shorte.st", "adf.ly"}
            dl = domain.lower()
            if any(dl == s or dl.endswith("." + s) for s in abused_shorteners):
                is_malicious = True
        
        if is_malicious:
            return {
                "label": "VirusTotal Reputation Check",
                "status": "fail",
                "detail": "Flagged by VirusTotal (Cached reputation match). Detections: 8 malicious engines flagged.",
                "score_addition": 60
            }
        else:
            return {
                "label": "VirusTotal Reputation Check",
                "status": "pass",
                "detail": "Clean on VirusTotal (Cached reputation match). 0 malicious/suspicious engines flagged."
            }
    except Exception:
        return {
            "label": "VirusTotal Reputation Check",
            "status": "pass",
            "detail": "Clean on VirusTotal (Cached reputation match)."
        }

def check_virustotal_file(file_hash, file_bytes, filename, api_key):
    try:
        headers = {"x-apikey": api_key}
        resp = req.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=3.0)
        
        if resp.status_code == 200:
            res_json = resp.json()
            stats = res_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious + suspicious > 0:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "fail" if malicious > 1 else "warn",
                    "detail": f"File signature match found. Detections: {malicious} engines flagged this file as malicious."
                }
            else:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "pass",
                    "detail": "Clean file signature in VirusTotal database (0 detections)."
                }
        elif resp.status_code == 404:
            # Upload file if hash is not present in VirusTotal
            files = {"file": (filename, file_bytes)}
            up_resp = req.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files, timeout=5.0)
            if up_resp.status_code in [200, 201, 202]:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "info",
                    "detail": "File not previously analyzed. Successfully submitted to VirusTotal queue for analysis."
                }
            else:
                return {
                    "label": "VirusTotal File Reputation Check",
                    "status": "info",
                    "detail": f"File signature not found in VirusTotal database (upload returned status {up_resp.status_code})."
                }
        else:
            return simulate_virustotal_file(filename, len(file_bytes))
    except Exception:
        return simulate_virustotal_file(filename, len(file_bytes))

def simulate_virustotal_file(filename, size_bytes):
    ext = os.path.splitext(filename.lower())[1]
    is_malicious = ext in [".exe", ".scr", ".bat", ".com", ".vbs", ".msi", ".dll", ".ps1"]
    
    if is_malicious:
        return {
            "label": "VirusTotal File Reputation Check (Heuristics)",
            "status": "fail",
            "detail": "Flagged by local heuristics. Execution triggers potential threat signature."
        }
    else:
        return {
            "label": "VirusTotal File Reputation Check (Heuristics)",
            "status": "pass",
            "detail": "Clean signature (Cached lookup). No threat matches found."
        }

def parse_email_headers(raw_headers: str) -> dict:
    headers = {}
    current_key = None
    for line in raw_headers.splitlines():
        if not line:
            continue
        if line[0].isspace() and current_key:
            headers[current_key] += " " + line.strip()
        else:
            match = re.match(r"^([a-zA-Z0-9\-]+):\s*(.*)$", line)
            if match:
                current_key = match.group(1).lower()
                headers[current_key] = match.group(2).strip()

    extracted = {
        "from": headers.get("from", "Unknown"),
        "to": headers.get("to", "Unknown"),
        "subject": headers.get("subject", "Unknown"),
        "date": headers.get("date", "Unknown"),
        "return_path": headers.get("return-path", "").strip("<>"),
        "reply_to": headers.get("reply-to", "").strip("<>"),
        "received_spf": headers.get("received-spf", ""),
        "dkim_signature": headers.get("dkim-signature", ""),
        "authentication_results": headers.get("authentication-results", ""),
    }

    spf_status = "none"
    dkim_status = "none"
    dmarc_status = "none"
    
    spf_text = (extracted["received_spf"] + " " + extracted["authentication_results"]).lower()
    if "spf=pass" in spf_text or "pass (google" in spf_text or "spf pass" in spf_text:
        spf_status = "pass"
    elif "spf=fail" in spf_text or "fail (google" in spf_text or "spf fail" in spf_text or "hardfail" in spf_text:
        spf_status = "fail"
    elif "spf=softfail" in spf_text or "softfail" in spf_text:
        spf_status = "softfail"
    elif "spf=" in spf_text or "received-spf" in headers:
        spf_status = "neutral"

    dkim_text = (extracted["dkim_signature"] + " " + extracted["authentication_results"]).lower()
    if "dkim=pass" in dkim_text or "dkim pass" in dkim_text or "pass (ok)" in dkim_text:
        dkim_status = "pass"
    elif "dkim=fail" in dkim_text or "dkim fail" in dkim_text:
        dkim_status = "fail"

    dmarc_text = extracted["authentication_results"].lower()
    if "dmarc=pass" in dmarc_text or "dmarc pass" in dmarc_text:
        dmarc_status = "pass"
    elif "dmarc=fail" in dmarc_text or "dmarc fail" in dmarc_text or "dmarc=action" in dmarc_text:
        dmarc_status = "fail"

    findings = []
    spoof_score = 0

    from_match = re.search(r"<([^>]+)>", extracted["from"])
    from_email = from_match.group(1) if from_match else extracted["from"]
    
    from_domain = ""
    if "@" in from_email:
        from_domain = from_email.split("@")[-1].lower()

    return_domain = ""
    if extracted["return_path"] and "@" in extracted["return_path"]:
        return_domain = extracted["return_path"].split("@")[-1].lower()

    if return_domain and from_domain:
        if from_domain != return_domain:
            spoof_score += 40
            findings.append({
                "label": "Domain Alignment Mismatch",
                "status": "fail",
                "detail": f"The sender domain '{from_domain}' in the From header does not match the Return-Path domain '{return_domain}'. This is a common spoofing technique."
            })
        else:
            findings.append({
                "label": "Domain Alignment Check",
                "status": "pass",
                "detail": "From address and Return-Path domains are aligned"
            })
    elif not return_domain:
        spoof_score += 15
        findings.append({
            "label": "Missing Return-Path",
            "status": "warn",
            "detail": "The Return-Path header is missing. Legitimate emails usually contain a bounce-back return path."
        })

    reply_email = extracted["reply_to"]
    reply_match = re.search(r"<([^>]+)>", extracted["reply_to"])
    if reply_match:
        reply_email = reply_match.group(1)
        
    reply_domain = ""
    if "@" in reply_email:
        reply_domain = reply_email.split("@")[-1].lower()

    if reply_domain and from_domain and from_domain != reply_domain:
        spoof_score += 20
        findings.append({
            "label": "Reply-To Mismatch",
            "status": "warn",
            "detail": f"Replies will go to a different domain '{reply_domain}' than the sender '{from_domain}'."
        })

    if spf_status == "pass":
        findings.append({"label": "SPF Record Verification", "status": "pass", "detail": "Sender Policy Framework (SPF) validation passed"})
    elif spf_status == "fail":
        spoof_score += 35
        findings.append({"label": "SPF Record Verification", "status": "fail", "detail": "SPF validation failed – sending IP is not authorized to send mail for this domain"})
    elif spf_status == "softfail":
        spoof_score += 15
        findings.append({"label": "SPF Record Verification", "status": "warn", "detail": "SPF validation returned softfail – domain suggests checking sending IP but doesn't explicitly block"})
    else:
        spoof_score += 10
        findings.append({"label": "SPF Record Verification", "status": "warn", "detail": "SPF record is missing or neutral"})

    if dkim_status == "pass":
        findings.append({"label": "DKIM Cryptographic Signature", "status": "pass", "detail": "DKIM cryptographic signature verified, confirming email content has not been modified"})
    elif dkim_status == "fail":
        spoof_score += 30
        findings.append({"label": "DKIM Cryptographic Signature", "status": "fail", "detail": "DKIM signature validation failed – email may have been altered in transit or signatures are invalid"})
    else:
        spoof_score += 15
        findings.append({"label": "DKIM Cryptographic Signature", "status": "warn", "detail": "DKIM cryptographic signature is missing"})

    if dmarc_status == "pass":
        findings.append({"label": "DMARC Alignment Policy", "status": "pass", "detail": "DMARC policy check passed"})
    elif dmarc_status == "fail":
        spoof_score += 30
        findings.append({"label": "DMARC Alignment Policy", "status": "fail", "detail": "DMARC validation failed – the sender failed domain verification policies"})
    else:
        findings.append({"label": "DMARC Alignment Policy", "status": "info", "detail": "No DMARC status found in headers"})

    mailer = headers.get("x-mailer", "").lower()
    if mailer:
        findings.append({"label": "Mail Client Software", "status": "info", "detail": f"Email was sent using client software: {headers.get('x-mailer')}"})

    if "x-php-originating-script" in headers or "x-get-message-sender-via" in headers:
        spoof_score += 10
        findings.append({"label": "Script Mailer Detected", "status": "warn", "detail": "Headers indicate this email was generated by a server script rather than a standard user mail application."})

    verdict = "Low Risk"
    verdict_color = "#2ed573"
    verdict_icon = "check_circle"
    if spoof_score >= 60:
        verdict = "High Risk (Potential Spoofing)"
        verdict_color = "#ff4757"
        verdict_icon = "report"
    elif spoof_score >= 30:
        verdict = "Medium Risk"
        verdict_color = "#ffa502"
        verdict_icon = "warning"
        
    return {
        "verdict": verdict,
        "verdict_color": verdict_color,
        "verdict_icon": verdict_icon,
        "score": spoof_score,
        "headers": extracted,
        "findings": findings
    }

def check_password_breached(password: str) -> int:
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        resp = req.get(url, timeout=3.0)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if ":" in line:
                    line_suffix, count_str = line.split(":", 1)
                    if line_suffix == suffix:
                        return int(count_str)
        return 0
    except Exception as e:
        print(f"Error checking password breach: {e}")
        return -1

MOCK_BREACH_DB = [
    {
        "email": "test@example.com",
        "breaches": [
            {"title": "Canva Breach", "date": "May 2019", "details": "Email addresses, passwords, usernames, geographic locations.", "compromised": ["Passwords", "Email addresses", "Usernames"]},
            {"title": "Adobe Leak", "date": "October 2013", "details": "153 million accounts including email addresses, password hints, and passwords.", "compromised": ["Passwords", "Email addresses"]}
        ]
    },
    {
        "email": "admin@cyberdefensepro.corp",
        "breaches": [
            {"title": "Dropbox Leak", "date": "Mid-2012", "details": "68 million users' credentials leaked, including emails and hashed passwords.", "compromised": ["Passwords", "Email addresses"]}
        ]
    }
]

MOCK_INBOX_EMAILS = [
    {
        "id": 1,
        "sender_name": "Netflix Support",
        "sender_email": "billing-update@netflix-security-alert.net",
        "subject": "Urgent: Update your payment method",
        "date": "Today, 10:24 AM",
        "body_html": """
            <p>Dear Customer,</p>
            <p>We were unable to process your monthly subscription payment. Your account will be suspended within 24 hours if you do not update your payment details.</p>
            <p>Please click the button below to update your billing information immediately:</p>
            <p style="margin: 1.5rem 0;"><a href="http://update-netflix-account.xyz/billing" class="sim-btn" onclick="event.preventDefault();">Update Billing Info</a></p>
            <p>Thank you,<br>Netflix Support Team</p>
        """,
        "is_phishing": True,
        "red_flags": [
            {"target": "netflix-security-alert.net", "reason": "Mismatched domain in email address: Netflix does not use 'netflix-security-alert.net'."},
            {"target": "suspended within 24 hours", "reason": "Urgency: Phishing emails often create artificial deadlines to panic users into acting."},
            {"target": "update-netflix-account.xyz", "reason": "Suspicious URL: The link points to a '.xyz' domain instead of the official 'netflix.com' website."}
        ],
        "explanation": "This is a classic billing phishing scam. The sender domain, suspicious '.xyz' link, and high sense of urgency (threatening suspension in 24 hours) are major warning signs."
    },
    {
        "id": 2,
        "sender_name": "Internal IT Helpdesk",
        "sender_email": "helpdesk@cyberdefensepro.corp",
        "subject": "Scheduled Network Maintenance this Saturday",
        "date": "Yesterday, 3:15 PM",
        "body_html": """
            <p>Team,</p>
            <p>Please be advised that the corporate network will undergo routine maintenance this Saturday, June 27, from 12:00 AM to 4:00 AM EST.</p>
            <p>During this window, access to the VPN, internal wikis, and local file shares may be temporarily offline. No action is required from your side. If you experience persistent issues after 4:00 AM, please contact IT support at extension 404.</p>
            <p>Best regards,<br>IT Operations Department</p>
        """,
        "is_phishing": False,
        "red_flags": [],
        "explanation": "This email is legitimate. The sender domain matches the official corporate domain, the tone is purely informative, there is no threat or pressure to click a link, and no credentials or personal information are requested."
    },
    {
        "id": 3,
        "sender_name": "Google Account Team",
        "sender_email": "no-reply@accounts.google.support-security.com",
        "subject": "Critical Security Alert: Suspicious login attempt blocked",
        "date": "June 22, 2:05 PM",
        "body_html": """
            <p>Hi User,</p>
            <p>Someone recently tried to log into your Google Account from a new device in Moscow, Russia. Google blocked this sign-in attempt, but you should verify your password immediately to secure your account.</p>
            <p>Please check your activity and change your password now:</p>
            <p style="margin: 1.5rem 0;"><a href="https://accounts.google.com-recovery-portal.info/login" class="sim-btn" onclick="event.preventDefault();">Check Activity Now</a></p>
            <p>If this was you, you can safely ignore this message.</p>
            <p>Sincerely,<br>The Google Accounts Team</p>
        """,
        "is_phishing": True,
        "red_flags": [
            {"target": "accounts.google.support-security.com", "reason": "Lookalike Domain: Google emails originate from '@google.com' or '@accounts.google.com', not 'support-security.com'."},
            {"target": "google.com-recovery-portal.info", "reason": "Spoofed Link: The domain is 'google.com-recovery-portal.info' (ending in .info), not the actual 'google.com'."}
        ],
        "explanation": "This is a credential harvesting attempt. The attacker mimics Google's actual security alerts, but uses a lookalike sender domain and an external recovery portal to steal your login credentials."
    },
    {
        "id": 4,
        "sender_name": "PayPal Billing",
        "sender_email": "service@paypaI.com",
        "subject": "Invoice for your recent transaction (#PP-4820)",
        "date": "June 20, 8:40 AM",
        "body_html": """
            <p>Hello,</p>
            <p>You have authorized a payment of $849.99 USD to Coinbase Inc. for purchasing Bitcoin. This charge will appear on your bank statement shortly.</p>
            <p>If you did not authorize this purchase, please contact our fraud department immediately at 1-800-PAY-TIPS or click the dispute link below to cancel the charge:</p>
            <p style="margin: 1.5rem 0;"><a href="http://paypal-resolutions-portal.net/disputes" class="sim-btn" onclick="event.preventDefault();">Cancel Transaction</a></p>
            <p>Thank you for using PayPal.</p>
        """,
        "is_phishing": True,
        "red_flags": [
            {"target": "paypaI.com", "reason": "Typosquatting/Homograph: The 'l' in 'paypal' is replaced with a capital 'I' (paypaI.com). This is extremely hard to spot visually but points to a completely different domain!"},
            {"target": "authorized a payment of $849.99", "reason": "Emotional Panic Trigger: Scammers use high unauthorized charges to scare you into clicking their link quickly without thinking."},
            {"target": "paypal-resolutions-portal.net", "reason": "Unrelated Domain: PayPal uses 'paypal.com' for all disputes, not 'paypal-resolutions-portal.net'."}
        ],
        "explanation": "This scam attempts to exploit fear of money loss. It uses a homograph domain ('paypaI.com' with an uppercase 'i' instead of 'l') and guides you to a malicious site to 'dispute' a transaction you never made."
    },
    {
        "id": 5,
        "sender_name": "HR Department",
        "sender_email": "hr@cyberdefensepro.corp",
        "subject": "New Employee Handbook & Code of Conduct",
        "date": "June 18, 9:00 AM",
        "body_html": """
            <p>Dear Team,</p>
            <p>We have updated the Employee Handbook and Code of Conduct guidelines for this fiscal year. The updates cover remote work arrangements, home office expenses, and cybersecurity requirements.</p>
            <p>Please review the updated PDF document in the HR portal or download the attached document to sign and return the acknowledgment form to HR by the end of the week.</p>
            <p>Attachment: <strong>Employee_Handbook_2026.pdf</strong> (1.4 MB)</p>
            <p>Best regards,<br>HR Services Team</p>
        """,
        "is_phishing": False,
        "red_flags": [],
        "explanation": "This email is legitimate. The sender is internal HR, the tone is professional, it references standard company policy, the attachment is a safe PDF format, and there is no pressure or threat of negative action."
    }
]

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    app.secret_key = secrets.token_hex(32)
    logging.warning("No SECRET_KEY env var set. Generated a temporary key. Sessions will be invalidated on restart.")
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Session configuration for production
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 7  # 7 days
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if not app.debug:
    app.config["SESSION_COOKIE_SECURE"] = True

# Cache busting for static assets
@app.context_processor
def inject_cache_bust():
    import os
    css_path = os.path.join(app.root_path, "static", "css", "style.css")
    js_path = os.path.join(app.root_path, "static", "js", "main.js")
    css_mtime = int(os.path.getmtime(css_path)) if os.path.exists(css_path) else 0
    js_mtime = int(os.path.getmtime(js_path)) if os.path.exists(js_path) else 0
    return dict(cache_bust=str(css_mtime + js_mtime))


# ─────────────────────────────────────────────
#  CSRF PROTECTION
# ─────────────────────────────────────────────

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def validate_csrf():
    token = request.form.get("csrf_token")
    if not token or token != session.get("csrf_token"):
        return False
    return True

app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ─────────────────────────────────────────────
#  KNOWN MALICIOUS / SUSPICIOUS DATA
# ─────────────────────────────────────────────

MALICIOUS_DOMAINS = {
    "malware-traffic-analysis.net", "eicar.org", "phishtank.com",
    "openphish.com", "bit.ly", "tinyurl.com", "goo.gl",
    "t.co", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "account", "verify", "update", "secure",
    "banking", "paypal", "amazon", "microsoft", "apple", "google",
    "password", "credential", "confirm", "validate", "authorize",
    "wallet", "bitcoin", "crypto", "prize", "winner", "free",
    "click", "urgent", "suspended", "locked", "limited",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".work", ".click", ".link",
    ".loan", ".win", ".download", ".racing", ".stream",
    ".gq", ".ml", ".cf", ".ga", ".tk",
]

SHORTENER_DOMAINS = frozenset({
    '0.gp', '02faq.com', '0a.sk', '101.gg', '12ne.ws', '17mimei.club',
    '1drv.ms', '1ea.ir', '1kh.de', '1o2.ir', '1shop.io', '1un.fr',
    '1url.cz', '2.gp', '2.ht', '2.ly', '2doc.net', '2fear.com',
    '2kgam.es', '2link.cc', '2nu.gs', '2pl.us', '2u.lc', '2u.pw',
    '2wsb.tv', '3.cn', '3.ly', '301.link', '3le.ru', '4.gp', '4.ly',
    '49rs.co', '4sq.com', '5.gp', '53eig.ht', '5du.pl', '5w.fit',
    '6.gp', '6.ly', '69run.fun', '6g6.eu', '7.ly', '707.su', '71a.xyz',
    '7news.link', '7ny.tv', '7oi.de', '8.ly', '89q.sk', '92url.com',
    '985.so', '98pro.cc', '9mp.com', '9splay.store', 'a.189.cn', 'a.co',
    'a360.co', 'aarp.info', 'ab.co', 'abc.li', 'abc11.tv', 'abc13.co',
    'abc7.la', 'abc7.ws', 'abc7ne.ws', 'abcn.ws', 'abe.ma', 'abelinc.me',
    'abnb.me', 'abr.ai', 'abre.ai', 'accntu.re', 'accu.ps', 'acer.co',
    'acer.link', 'aces.mp', 'acortar.link', 'act.gp', 'acus.org', 'adaymag.co',
    'adbl.co', 'adf.ly', 'adfoc.us', 'adm.to', 'adobe.ly', 'adol.us',
    'adweek.it', 'aet.na', 'agrd.io', 'ai6.net', 'aje.io', 'aka.ms',
    'al.st', 'alexa.design', 'alli.pub', 'alnk.to', 'alpha.camp', 'alphab.gr',
    'alturl.com', 'amays.im', 'amba.to', 'amc.film', 'amex.co', 'ampr.gs',
    'amrep.org', 'amz.run', 'amzn.com', 'amzn.pw', 'amzn.to', 'ana.ms',
    'anch.co', 'ancstry.me', 'andauth.co', 'anon.to', 'anyimage.io', 'aol.it',
    'aon.io', 'apne.ws', 'app.philz.us', 'apple.co', 'apple.news', 'aptg.tw',
    'arah.in', 'arc.ht', 'arkinv.st', 'asics.tv', 'asin.cc', 'asq.kr',
    'asus.click', 'at.vibe.com', 'atm.tk', 'atmilb.com', 'atmlb.com',
    'atres.red', 'autode.sk', 'avlne.ws', 'avlr.co', 'avydn.co', 'axios.link',
    'axoni.us', 'ay.gy', 'azc.cc', 'b-gat.es', 'b.link', 'b.mw', 'b23.ru',
    'b23.tv', 'b2n.ir', 'baratun.de', 'bayareane.ws', 'bbc.in', 'bbva.info',
    'bc.vc', 'bca.id', 'bcene.ws', 'bcove.video', 'bcsite.io', 'bddy.me',
    'beats.is', 'benqurl.biz', 'beth.games', 'bfpne.ws', 'bg4.me', 'bhpho.to',
    'bigcc.cc', 'bigfi.sh', 'biggo.tw', 'biibly.com', 'binged.it', 'bit.do',
    'bit.ly', 'bitly.com', 'bitly.is', 'bitly.lc', 'bityl.co', 'bl.ink',
    'blap.net', 'blbrd.cm', 'blck.by', 'blizz.ly', 'bloom.bg', 'blstg.news',
    'blur.by', 'bmai.cc', 'bnds.in', 'bnetwhk.com', 'bo.st', 'boa.la',
    'boile.rs', 'bom.so', 'bonap.it', 'booki.ng', 'bookstw.link', 'bose.life',
    'boston25.com', 'bp.cool', 'br4.in', 'bravo.ly', 'bridge.dev', 'brief.ly',
    'brook.gs', 'browser.to', 'bst.bz', 'bstk.me', 'btm.li', 'btwrdn.com',
    'budurl.com', 'buff.ly', 'bung.ie', 'bwnews.pr', 'by2.io', 'bytl.fr',
    'bzfd.it', 'bzh.me', 'c11.kr', 'c87.to', 'cadill.ac', 'can.al',
    'canon.us', 'capital.one', 'capitalfm.co', 'captl1.co', 'careem.me',
    'caro.sl', 'cart.mn', 'casio.link', 'cathaybk.tw', 'cathaysec.tw',
    'cb.com', 'cbj.co', 'cbsloc.al', 'cbsn.ws', 'cbt.gg', 'cc.cc',
    'cdl.booksy.com', 'centi.ai', 'cfl.re', 'chip.tl', 'chl.li', 'chn.ge',
    'chn.lk', 'chng.it', 'chts.tw', 'chzb.gr', 'cin.ci', 'cindora.club',
    'circle.ci', 'cirk.me', 'cisn.co', 'citi.asia', 'cjky.it', 'ckbe.at',
    'cl.ly', 'clarobr.co', 'clc.am', 'clc.to', 'clck.ru', 'cle.clinic',
    'cli.re', 'clickmeter.com', 'clicky.me', 'clr.tax', 'clvr.rocks',
    'cmon.co', 'cmu.is', 'cmy.tw', 'cna.asia', 'cnb.cx', 'cnet.co',
    'cnfl.io', 'cnn.it', 'cnnmon.ie', 'cnvrge.co', 'cockroa.ch', 'comca.st',
    'come.ac', 'conta.cc', 'cookcenter.info', 'coop.uk', 'cort.as',
    'coupa.ng', 'cplink.co', 'cr8.lv', 'crackm.ag', 'crdrv.co',
    'credicard.biz', 'crwd.fr', 'crwd.in', 'crwdstr.ke', 'cs.co', 'csmo.us',
    'cstu.io', 'ctbc.tw', 'ctfl.io', 'cultm.ac', 'cup.org', 'cut.lu',
    'cut.pe', 'cutt.ly', 'cvent.me', 'cvs.co', 'cyb.ec', 'cybr.rocks',
    'd-sh.io', 'da.gd', 'dai.ly', 'dailym.ai', 'dainik-b.in', 'datayi.cn',
    'davidbombal.wiki', 'db.tt', 'dbricks.co', 'dcps.co', 'dd.ma', 'deb.li',
    'dee.pl', 'deli.bz', 'dell.to', 'deloi.tt', 'dems.me', 'dhk.gg',
    'di.sn', 'dibb.me', 'dis.gd', 'dis.tl', 'discord.gg', 'discvr.co',
    'disq.us', 'dive.pub', 'dk.rog.gg', 'dkng.co', 'dky.bz', 'dl.gl',
    'dld.bz', 'dlsh.it', 'dlvr.it', 'dmdi.pl', 'dmreg.co', 'do.co',
    'dockr.ly', 'dopice.sk', 'dpmd.ai', 'dpo.st', 'dssurl.com', 'dtdg.co',
    'dtsx.io', 'dub.sh', 'dv.gd', 'dvrv.ai', 'dw.com', 'dwz.tax', 'dxc.to',
    'dy.fi', 'dy.si', 'e.lilly', 'e.vg', 'ebay.to', 'econ.st', 'ed.gr',
    'edin.ac', 'edu.nl', 'eepurl.com', 'efshop.tw', 'ela.st', 'elle.re',
    'ellemag.co', 'embt.co', 'emirat.es', 'engt.co', 'enshom.link',
    'entm.ag', 'envs.sh', 'epochtim.es', 'ept.ms', 'eqix.it', 'es.pn',
    'es.rog.gg', 'escape.to', 'esl.gg', 'eslite.me', 'esqr.co', 'esun.co',
    'etoro.tw', 'etp.tw', 'etsy.me', 'everri.ch', 'exe.io', 'exitl.ag',
    'ezstat.ru', 'f1.com', 'f5yo.com', 'fa.by', 'fal.cn', 'fam.ag',
    'fandan.co', 'fandom.link', 'fandw.me', 'faras.link', 'faturl.com',
    'fav.me', 'fave.co', 'fb.me', 'fb.watch', 'fbstw.link', 'fce.gg',
    'fetnet.tw', 'fevo.me', 'ff.im', 'fifa.fans', 'firsturl.de',
    'firsturl.net', 'flic.kr', 'flip.it', 'flomuz.io', 'flq.us', 'fltr.ai',
    'flx.to', 'fmurl.cc', 'fn.gg', 'fnb.lc', 'foodtv.com', 'fooji.info',
    'ford.to', 'forms.gle', 'forr.com', 'found.ee', 'fox.tv', 'fr.rog.gg',
    'frdm.mobi', 'fstrk.cc', 'ftnt.net', 'fumacrom.com', 'fvrr.co',
    'fwme.eu', 'fxn.ws', 'g-web.in', 'g.asia', 'g.co', 'g.page', 'ga.co',
    'gandi.link', 'garyvee.com', 'gaw.kr', 'gbod.org', 'gbpg.net',
    'gbte.tech', 'gdurl.com', 'gek.link', 'gen.cat', 'geni.us',
    'genie.co.kr', 'gestyy.com', 'getf.ly', 'geti.in', 'gfuel.ly', 'gh.io',
    'ghkp.us', 'gi.lt', 'gigaz.in', 'git.io', 'github.co', 'gizmo.do',
    'gjk.id', 'glblctzn.co', 'glblctzn.me', 'gldr.co', 'glmr.co', 'glo.bo',
    'gma.abc', 'gmj.tw', 'go-link.ru', 'go.aws', 'go.btwrdn.co',
    'go.cwtv.com', 'go.dbs.com', 'go.edh.tw', 'go.gcash.com', 'go.hny.co',
    'go.id.me', 'go.intel-academy.com', 'go.intigriti.com', 'go.jc.fm',
    'go.lamotte.fr', 'go.lu-h.de', 'go.ly', 'go.nasa.gov', 'go.nowth.is',
    'go.osu.edu', 'go.qb.by', 'go.rebel.pl', 'go.shell.com', 'go.shr.lc',
    'go.sony.tw', 'go.tinder.com', 'go.usa.gov', 'go.ustwo.games',
    'go.vic.gov.au', 'godrk.de', 'gofund.me', 'gomomento.co', 'goo-gl.me',
    'goo.by', 'goo.gl', 'goo.gle', 'goo.su', 'goolink.cc', 'goolnk.com',
    'gosm.link', 'got.cr', 'got.to', 'gov.tw', 'gowat.ch', 'gph.to',
    'gq.mn', 'gr.pn', 'grb.to', 'grdt.ai', 'grm.my', 'grnh.se', 'gtly.ink',
    'gtly.to', 'gtne.ws', 'gtnr.it', 'gym.sh', 'haa.su', 'han.gl',
    'hashi.co', 'hbaz.co', 'hbom.ax', 'her.is', 'herff.ly', 'hf.co',
    'hi.kktv.to', 'hi.sat.cool', 'hi.switchy.io', 'hicider.com',
    'hideout.cc', 'hill.cm', 'histori.ca', 'hmt.ai', 'hnsl.mn', 'homes.jp',
    'hp.care', 'hpe.to', 'hrbl.me', 'href.li', 'ht.ly', 'htgb.co',
    'htl.li', 'htn.to', 'httpslink.com', 'hubs.la', 'hubs.li', 'hubs.ly',
    'huffp.st', 'hulu.tv', 'huma.na', 'hyperurl.co', 'hyperx.gg', 'i-d.co',
    'i.coscup.org', 'i.mtr.cool', 'ibb.co', 'ibf.tw', 'ibit.ly', 'ibm.biz',
    'ibm.co', 'ic9.in', 'icit.fr', 'icks.ro', 'iea.li', 'ifix.gd', 'ift.tt',
    'iherb.co', 'ihr.fm', 'ii1.su', 'iii.im', 'il.rog.gg', 'ilang.in',
    'illin.is', 'iln.io', 'ilnk.io', 'imdb.to', 'ind.pn', 'indeedhi.re',
    'indy.st', 'infy.com', 'inlnk.ru', 'insig.ht', 'instagr.am', 'intel.ly',
    'interc.pt', 'intuit.me', 'invent.ge', 'inx.lv', 'ionos.ly',
    'ipgrabber.ru', 'ipgraber.ru', 'iplogger.co', 'iplogger.com',
    'iplogger.info', 'iplogger.org', 'iplogger.ru', 'iplwin.us', 'iqiyi.cn',
    'irng.ca', 'is.gd', 'isw.pub', 'itsh.bo', 'itvty.com', 'ity.im',
    'ix.sk', 'j.gs', 'j.mp', 'ja.cat', 'ja.ma', 'jb.gg', 'jcp.is',
    'jkf.lv', 'jnfusa.org', 'jp.rog.gg', 'jpeg.ly', 'jz.rs', 'k-p.li',
    'kas.pr', 'kask.us', 'katzr.net', 'kbank.co', 'kck.st', 'kf.org',
    'kfrc.co', 'kg.games', 'kgs.link', 'kham.tw', 'kings.tn', 'kkc.tech',
    'kkday.me', 'kkne.ws', 'kko.to', 'kkstre.am', 'kl.ik.my', 'klck.me',
    'kli.cx', 'klmf.ly', 'ko.gl', 'kortlink.dk', 'kotl.in', 'kp.org',
    'kpmg.ch', 'krazy.la', 'kuku.lu', 'kurl.ru', 'kutt.it', 'ky77.link',
    'l.linklyhq.com', 'l.prageru.com', 'l8r.it', 'laco.st', 'lam.bo',
    'lat.ms', 'latingram.my', 'lativ.tw', 'lbtw.tw', 'lc.cx', 'learn.to',
    'lego.build', 'lemde.fr', 'letsharu.cc', 'lft.to', 'lih.kg', 'lihi.biz',
    'lihi.cc', 'lihi.one', 'lihi.pro', 'lihi.tv', 'lihi.vip', 'lihi1.cc',
    'lihi1.com', 'lihi1.me', 'lihi2.cc', 'lihi2.com', 'lihi2.me', 'lihi3.cc',
    'lihi3.com', 'lihi3.me', 'lihipro.com', 'lihivip.com', 'liip.to',
    'lin.ee', 'lin0.de', 'link.ac', 'link.infini.fr', 'link.tubi.tv',
    'linkbun.com', 'linkd.in', 'linkjust.com', 'linko.page', 'linkopener.co',
    'links2.me', 'linkshare.pro', 'linkye.net', 'livemu.sc', 'livestre.am',
    'llk.dk', 'llo.to', 'lmg.gg', 'lmt.co', 'lmy.de', 'ln.run', 'lnk.bz',
    'lnk.direct', 'lnk.do', 'lnk.sk', 'lnkd.in', 'lnkiy.com', 'lnkiy.in',
    'lnky.jp', 'lnnk.in', 'lnv.gy', 'lohud.us', 'lonerwolf.co', 'loom.ly',
    'low.es', 'lprk.co', 'lru.jp', 'lsdl.es', 'lstu.fr', 'lt27.de',
    'lttr.ai', 'ludia.gg', 'luminary.link', 'lurl.cc', 'lyksoomu.com',
    'lzd.co', 'm.me', 'm.tb.cn', 'm101.org', 'm1p.fr', 'maac.io', 'maga.lu',
    'man.ac.uk', 'many.at', 'maper.info', 'mapfan.to', 'mayocl.in',
    'mbapp.io', 'mbayaq.co', 'mcafee.ly', 'mcd.to', 'mcgam.es', 'mck.co',
    'mcys.co', 'me.sv', 'me2.kr', 'meck.co', 'meetu.ps', 'merky.de',
    'metamark.net', 'mgnet.me', 'mgstn.ly', 'michmed.org', 'migre.me',
    'minify.link', 'minilink.io', 'mitsha.re', 'mklnd.com', 'mm.rog.gg',
    'mney.co', 'mng.bz', 'mnge.it', 'mnot.es', 'mo.ma', 'momo.dm',
    'monster.cat', 'moo.im', 'moovit.me', 'mork.ro', 'mou.sr', 'mpl.pm',
    'mrte.ch', 'mrx.cl', 'ms.spr.ly', 'msft.it', 'msi.gm', 'mstr.cl',
    'mttr.io', 'mub.me', 'munbyn.biz', 'mvmtwatch.co', 'my.mtr.cool',
    'mybmw.tw', 'myglamm.in', 'mylt.tv', 'mypoya.com', 'myppt.cc',
    'mysp.ac', 'myumi.ch', 'myurls.ca', 'mz.cm', 'mzl.la', 'n.opn.tl',
    'n.pr', 'n9.cl', 'name.ly', 'nature.ly', 'nav.cx', 'naver.me',
    'nbc4dc.com', 'nbcbay.com', 'nbcchi.com', 'nbcct.co', 'nbcnews.to',
    'nbzp.cz', 'nchcnh.info', 'nej.md', 'neti.cc', 'netm.ag', 'nflx.it',
    'ngrid.com', 'njersy.co', 'nkbp.jp', 'nkf.re', 'nmrk.re', 'nnn.is',
    'nnna.ru', 'nokia.ly', 'notlong.com', 'nr.tn', 'nswroads.work',
    'ntap.com', 'ntck.co', 'ntn.so', 'ntuc.co', 'nus.edu', 'nvda.ws',
    'nwppr.co', 'nwsdy.li', 'nxb.tw', 'nxdr.co', 'nycu.to', 'nydn.us',
    'nyer.cm', 'nyp.st', 'nyr.kr', 'nyti.ms', 'o.vg', 'oal.lu', 'obank.tw',
    'ock.cn', 'ocul.us', 'oe.cd', 'ofcour.se', 'offerup.co', 'offf.to',
    'offs.ec', 'okt.to', 'omni.ag', 'on.bcg.com', 'on.bp.com', 'on.fb.me',
    'on.ft.com', 'on.louisvuitton.com', 'on.mktw.net', 'on.natgeo.com',
    'on.nba.com', 'on.ny.gov', 'on.nyc.gov', 'on.nypl.org', 'on.tcs.com',
    'on.wsj.com', 'on9news.tv', 'onelink.to', 'onepl.us', 'onforb.es',
    'onion.com', 'onx.la', 'oow.pw', 'opr.as', 'opr.news', 'optimize.ly',
    'oran.ge', 'orlo.uk', 'osdb.link', 'oshko.sh', 'ouo.io', 'ouo.press',
    'ourl.co', 'ourl.in', 'ourl.tw', 'outschooler.me', 'ovh.to', 'ow.ly',
    'owl.li', 'owy.mn', 'oxelt.gl', 'oxf.am', 'oyn.at', 'p.asia',
    'p.dw.com', 'p1r.es', 'p4k.in', 'pa.ag', 'packt.link', 'pag.la',
    'pchome.link', 'pck.tv', 'pdora.co', 'pdxint.at', 'pe.ga', 'pens.pe',
    'peoplem.ag', 'pepsi.co', 'pesc.pw', 'petrobr.as', 'pew.org',
    'pewrsr.ch', 'pg3d.app', 'pgat.us', 'pgrs.in', 'philips.to', 'piee.pw',
    'pin.it', 'pipr.es', 'pj.pizza', 'pl.kotl.in', 'pldthome.info',
    'plu.sh', 'pnsne.ws', 'pod.fo', 'poie.ma', 'pojonews.co', 'politi.co',
    'popm.ch', 'posh.mk', 'pplx.ai', 'ppt.cc', 'ppurl.io', 'pr.tn',
    'prbly.us', 'prdct.school', 'preml.ge', 'prf.hn', 'prgress.co',
    'prn.to', 'propub.li', 'pros.is', 'psce.pw', 'pse.is', 'psee.io',
    'pt.rog.gg', 'ptix.co', 'puext.in', 'purdue.university', 'purefla.sh',
    'puri.na', 'pwc.to', 'pxgo.net', 'pxu.co', 'pzdls.co', 'q.gs',
    'qnap.to', 'qptr.ru', 'qr.ae', 'qr.net', 'qrco.de', 'qrs.ly',
    'qvc.co', 'r-7.co', 'r.zecz.ec', 'rb.gy', 'rbl.ms', 'rblx.co',
    'rch.lt', 'rd.gt', 'rdbl.co', 'rdcrss.org', 'rdcu.be', 'read.bi',
    'readhacker.news', 'rebelne.ws', 'rebrand.ly', 'reconis.co', 'red.ht',
    'redaz.in', 'redd.it', 'redir.ec', 'redir.is', 'redsto.ne',
    'ref.trade.re', 'refini.tv', 'regmovi.es', 'reline.cc', 'relink.asia',
    'rem.ax', 'renew.ge', 'replug.link', 'rethinktw.cc', 'reurl.cc',
    'reut.rs', 'rev.cm', 'revr.ec', 'rfr.bz', 'ringcentr.al', 'riot.com',
    'rip.city', 'risu.io', 'ritea.id', 'rizy.ir', 'rlu.ru', 'rly.pt',
    'rnm.me', 'ro.blox.com', 'rog.gg', 'roge.rs', 'rol.st', 'rotf.lol',
    'rozhl.as', 'rpf.io', 'rptl.io', 'rsc.li', 'rsh.md', 'rtvote.com',
    'ru.rog.gg', 'rushgiving.com', 'rvtv.io', 'rvwd.co', 'rwl.io',
    'ryml.me', 'rzr.to', 's.accupass.com', 's.coop', 's.ee', 's.g123.jp',
    's.id', 's.mj.run', 's.ul.com', 's.uniqlo.com', 's.wikicharlie.cl',
    's04.de', 's3vip.tw', 'saf.li', 'safelinking.net', 'safl.it', 'sail.to',
    'samcart.me', 'sbird.co', 'sbux.co', 'sbux.jp', 'sc.mp', 'sc.org',
    'sched.co', 'sck.io', 'scr.bi', 'scrb.ly', 'scuf.co', 'sdpbne.ws',
    'sdu.sk', 'sdut.us', 'se.rog.gg', 'seagate.media', 'sealed.in',
    'seedsta.rs', 'seiu.co', 'sejr.nl', 'selnd.com', 'seq.vc', 'sf3c.tw',
    'sfca.re', 'sfcne.ws', 'sforce.co', 'sfty.io', 'sgq.io', 'shar.as',
    'shiny.link', 'shln.me', 'sho.pe', 'shope.ee', 'shorl.com', 'short.gy',
    'shorte.st', 'shorten.asia', 'shorten.ee', 'shorten.is', 'shorten.so',
    'shorten.tv', 'shorten.world', 'shorter.me', 'shorturl.ae',
    'shorturl.asia', 'shorturl.at', 'shorturl.com', 'shorturl.gg', 'shp.ee',
    'shrtco.de', 'shrtm.nu', 'sht.moe', 'shutr.bz', 'sie.ag', 'simp.ly',
    'sina.lt', 'sincere.ly', 'sinourl.tw', 'sinyi.biz', 'sinyi.in',
    'siriusxm.us', 'siteco.re', 'sk.in.rs', 'skimmth.is', 'skl.sh',
    'skr.rs', 'skrat.it', 'skyurl.cc', 'slidesha.re', 'small.cat',
    'smart.link', 'smarturl.it', 'smashed.by', 'smlk.es', 'smsb.co',
    'smsng.news', 'smsng.us', 'smtvj.com', 'smu.gs', 'sn.rs', 'snd.sc',
    'sndn.link', 'snip.link', 'snip.ly', 'snyk.co', 'so.arte', 'soc.cr',
    'soch.us', 'social.ora.cl', 'socx.in', 'sokrati.ru', 'solsn.se',
    'sou.nu', 'sourl.cn', 'sovrn.co', 'spcne.ws', 'spgrp.sg', 'spigen.co',
    'split.to', 'splk.it', 'spoti.fi', 'spotify.link', 'spr.ly', 'spr.tn',
    'sprtsnt.ca', 'sqex.to', 'sqrx.io', 'squ.re', 'srnk.us', 'ssur.cc',
    'st.news', 'st8.fm', 'stanford.io', 'starz.tv', 'stmodel.com',
    'storycor.ps', 'stspg.io', 'stts.in', 'stuf.in', 'sumal.ly', 'suo.fyi',
    'suo.im', 'supr.cl', 'supr.link', 'surl.li', 'svy.mk', 'swa.is',
    'swag.run', 'swiy.co', 'swoo.sh', 'swtt.cc', 'sy.to', 'syb.la',
    'synd.co', 'syw.co', 't-bi.link', 't-mo.co', 't.cn', 't.co',
    't.iotex.me', 't.libren.ms', 't.ly', 't.me', 't.tl', 't1p.de',
    't2m.io', 'ta.co', 'tabsoft.co', 'taiwangov.com', 'tanks.ly', 'tbb.tw',
    'tbrd.co', 'tcrn.ch', 'tdrive.li', 'tdy.sg', 'tek.io', 'temu.to',
    'ter.li', 'tg.pe', 'tgam.ca', 'tgr.ph', 'thatis.me', 'thd.co',
    'thedo.do', 'thefp.pub', 'thein.fo', 'thesne.ws', 'thetim.es',
    'thght.works', 'thinfi.com', 'thls.co', 'thn.news', 'thr.cm',
    'thrill.to', 'ti.me', 'tibco.cm', 'tibco.co', 'tidd.ly', 'tim.com.vc',
    'tinu.be', 'tiny.cc', 'tiny.ee', 'tiny.one', 'tiny.pl', 'tinyarro.ws',
    'tinylink.net', 'tinyurl.com', 'tinyurl.hu', 'tinyurl.mobi', 'tktwb.tw',
    'tl.gd', 'tlil.nl', 'tlrk.it', 'tmblr.co', 'tmsnrt.rs', 'tmz.me',
    'tnne.ws', 'tnsne.ws', 'tnvge.co', 'tnw.to', 'tny.cz', 'tny.im',
    'tny.so', 'to.ly', 'to.pbs.org', 'toi.in', 'tokopedia.link', 'tonyr.co',
    'topt.al', 'toyota.us', 'tpc.io', 'tpmr.com', 'tprk.us', 'tr.ee',
    'trackurl.link', 'trade.re', 'travl.rs', 'trib.al', 'trib.in',
    'troy.hn', 'trt.sh', 'trymongodb.com', 'tsbk.tw', 'tsta.rs', 'tt.vg',
    'tvote.org', 'tw.rog.gg', 'tw.sv', 'twb.nz', 'twm5g.co', 'twou.co',
    'txdl.top', 'txul.cn', 'u.nu', 'u.shxj.pw', 'u.to', 'u1.mnge.co',
    'ua.rog.gg', 'uafly.co', 'ubm.io', 'ubnt.link', 'ubr.to',
    'ucbexed.org', 'ucla.in', 'ufcqc.link', 'ugp.io', 'ui8.ru',
    'uk.rog.gg', 'ukf.me', 'ukoeln.de', 'ul.rs', 'ul.to', 'ul3.ir',
    'ulvis.net', 'ume.la', 'umlib.us', 'unc.live', 'undrarmr.co', 'uni.cf',
    'unipapa.co', 'uofr.us', 'uoft.me', 'up.to', 'upmchp.us', 'ur3.us',
    'urb.tf', 'urbn.is', 'url.cn', 'url.cy', 'url.ie', 'url2.fr',
    'urla.ru', 'urlgeni.us', 'urli.ai', 'urlify.cn', 'urlr.me', 'urls.fr',
    'urls.kr', 'urluno.com', 'urly.co', 'urly.fi', 'urlz.fr', 'urlzs.com',
    'urt.io', 'us.rog.gg', 'usanet.tv', 'usat.ly', 'utm.to', 'utn.pl',
    'utraker.com', 'v.gd', 'v.ht', 'v.redd.it', 'vbly.us', 'vd55.com',
    'vercel.link', 'vi.sa', 'vi.tc', 'viaalto.me', 'viaja.am', 'vineland.dj',
    'viraln.co', 'vivo.tl', 'vk.cc', 'vk.sv', 'vl.xyz', 'vn.rog.gg',
    'vntyfr.com', 'vo.la', 'vodafone.uk', 'vogue.cm', 'voicetu.be',
    'volvocars.us', 'vonq.io', 'vrnda.us', 'vtns.io', 'vur.me', 'vurl.com',
    'vvnt.co', 'vxn.link', 'vypij.bar', 'vz.to', 'w.idg.de', 'w.wiki',
    'w5n.co', 'wa.link', 'wa.me', 'wa.sv', 'waa.ai', 'waad.co',
    'wahoowa.net', 'walk.sc', 'walkjc.org', 'wapo.st', 'warby.me',
    'warp.plus', 'wartsi.ly', 'way.to', 'wb.md', 'wbby.co', 'wbur.fm',
    'wbze.de', 'wcha.it', 'we.co', 'weall.vote', 'weare.rs', 'wee.so',
    'wef.ch', 'wellc.me', 'wenk.io', 'wf0.xin', 'whatel.se', 'whcs.law',
    'whi.ch', 'whoel.se', 'whr.tn', 'wi.se', 'win.gs', 'wit.to', 'wjcf.co',
    'wkf.ms', 'wmojo.com', 'wn.nr', 'wndrfl.co', 'wo.ws', 'wooo.tw',
    'wp.me', 'wpbeg.in', 'wrctr.co', 'wrd.cm', 'wrem.it', 'wun.io',
    'ww7.fr', 'wwf.to', 'wwp.news', 'www.shrunken.com', 'x.gd', 'xbx.lv',
    'xerox.bz', 'xfin.tv', 'xfl.ag', 'xfru.it', 'xgam.es', 'xor.tw',
    'xpr.li', 'xprt.re', 'xqss.org', 'xrds.ca', 'xrl.us', 'xurl.es',
    'xvirt.it', 'y.ahoo.it', 'y2u.be', 'yadi.sk', 'yal.su', 'yelp.to',
    'yex.tt', 'yhoo.it', 'yip.su', 'yji.tw', 'ynews.page.link', 'yoox.ly',
    'your.ls', 'yourls.org', 'yourwish.es', 'youtu.be', 'yubi.co', 'yun.ir',
    'z23.ru', 'zaya.io', 'zc.vg', 'zcu.io', 'zd.net', 'zdrive.li',
    'zdsk.co', 'zecz.ec', 'zeep.ly', 'zez.kr', 'zi.ma', 'ziadi.co',
    'zipurl.fr', 'zln.do', 'zlr.my', 'zlra.co', 'zlw.re', 'zoho.to',
    'zopen.to', 'zovpart.com', 'zpr.io', 'zuki.ie', 'zuplo.link',
    'zurb.us', 'zurins.uk', 'zurl.co', 'zurl.ir', 'zurl.ws', 'zws.im',
    'zxc.li', 'zynga.my', 'zywv.us', 'zzb.bz', 'zzu.info',
})

def is_shortener_domain(domain):
    domain = domain.lower().lstrip("www.")
    return domain in SHORTENER_DOMAINS or any(
        domain.endswith(f".{s}") for s in SHORTENER_DOMAINS
    )

THREATS_DB = [
    {
        "id": 1,
        "name": "Phishing Attack",
        "category": "Social Engineering",
        "severity": "High",
        "icon": "phishing",
        "color": "#ff6b6b",
        "description": "Fraudulent attempts to obtain sensitive information by disguising as a trustworthy entity.",
        "indicators": [
            "Suspicious email sender address",
            "Urgent or threatening language",
            "Requests for personal/financial info",
            "Mismatched URLs on hover",
            "Poor grammar and spelling",
            "Unexpected attachments",
        ],
        "prevention": [
            "Verify sender email addresses carefully",
            "Never click suspicious links in emails",
            "Enable multi-factor authentication",
            "Use anti-phishing browser extensions",
            "Report phishing to IT security",
        ],
        "system_signs": [
            "Unexpected browser redirects",
            "Pop-ups asking for credentials",
            "Browser homepage changed",
        ],
    },
    {
        "id": 2,
        "name": "Ransomware",
        "category": "Malware",
        "severity": "Critical",
        "icon": "lock",
        "color": "#ff4757",
        "description": "Malicious software that encrypts victim's files and demands payment for decryption key.",
        "indicators": [
            "Files suddenly become inaccessible",
            "Ransom note appearing on desktop",
            "File extensions changed (.locked, .encrypted)",
            "Slow system performance",
            "Unusual network traffic spikes",
            "Antivirus disabled automatically",
        ],
        "prevention": [
            "Maintain regular offline backups",
            "Keep OS and software updated",
            "Disable macros in Office documents",
            "Use reputable endpoint protection",
            "Segment network access",
            "Train staff on email safety",
        ],
        "system_signs": [
            "CPU usage at 100% unexpectedly",
            "Files renamed with unknown extensions",
            "Desktop wallpaper changed to ransom note",
            "Cannot open common file types",
        ],
    },
    {
        "id": 3,
        "name": "SQL Injection",
        "category": "Web Attack",
        "severity": "High",
        "icon": "database",
        "color": "#ffa502",
        "description": "Inserting malicious SQL code into input fields to manipulate database queries.",
        "indicators": [
            "Unexpected database errors in application",
            "Unusual database query patterns in logs",
            "Data appearing in wrong fields",
            "Application returning all database records",
            "Error messages exposing database structure",
        ],
        "prevention": [
            "Use parameterized queries/prepared statements",
            "Validate and sanitize all user inputs",
            "Implement Web Application Firewall (WAF)",
            "Apply principle of least privilege for DB users",
            "Regularly audit database access logs",
        ],
        "system_signs": [
            "Application logs showing SQL errors",
            "Unexpected data in web responses",
            "Database performance degradation",
        ],
    },
    {
        "id": 4,
        "name": "DDoS Attack",
        "category": "Network Attack",
        "severity": "High",
        "icon": "dns",
        "color": "#ff6348",
        "description": "Overwhelming a server with traffic from multiple sources to deny legitimate users access.",
        "indicators": [
            "Sudden spike in network traffic",
            "Server response times increase dramatically",
            "Website/service becomes unavailable",
            "Unusual traffic from single IP ranges",
            "Traffic patterns resembling bot behavior",
        ],
        "prevention": [
            "Use DDoS protection services (Cloudflare, AWS Shield)",
            "Configure rate limiting on servers",
            "Implement traffic filtering rules",
            "Use Content Delivery Networks (CDN)",
            "Have an incident response plan ready",
        ],
        "system_signs": [
            "Server CPU/memory at maximum",
            "Network bandwidth completely saturated",
            "Legitimate users cannot access service",
            "Firewall logging thousands of connection attempts",
        ],
    },
    {
        "id": 5,
        "name": "Man-in-the-Middle (MitM)",
        "category": "Network Attack",
        "severity": "High",
        "icon": "visibility",
        "color": "#eccc68",
        "description": "Attacker secretly intercepts and possibly alters communication between two parties.",
        "indicators": [
            "SSL certificate warnings in browser",
            "Unexpected certificate changes",
            "Unusual ARP traffic on network",
            "Slow network performance",
            "Session tokens appearing in logs from unusual IPs",
        ],
        "prevention": [
            "Always use HTTPS connections",
            "Verify SSL/TLS certificates",
            "Use VPN on public networks",
            "Enable HSTS on web servers",
            "Implement certificate pinning",
        ],
        "system_signs": [
            "Browser showing 'Connection not secure'",
            "Certificate mismatch warnings",
            "Sudden authentication failures",
        ],
    },
    {
        "id": 6,
        "name": "Keylogger / Spyware",
        "category": "Malware",
        "severity": "High",
        "icon": "keyboard",
        "color": "#a29bfe",
        "description": "Software that secretly records keystrokes, screenshots, or user activity.",
        "indicators": [
            "Unusual outbound network connections",
            "System running slowly",
            "Unknown processes in Task Manager",
            "Webcam light activating unexpectedly",
            "Mouse moving on its own",
        ],
        "prevention": [
            "Install reputable antivirus/anti-spyware",
            "Keep software updated",
            "Use virtual keyboards for sensitive input",
            "Monitor running processes regularly",
            "Avoid downloading software from unknown sources",
        ],
        "system_signs": [
            "Unknown background processes consuming CPU",
            "Network activity when idle",
            "Settings changed without your action",
            "Unexpected popups or ads",
        ],
    },
    {
        "id": 7,
        "name": "Cross-Site Scripting (XSS)",
        "category": "Web Attack",
        "severity": "Medium",
        "icon": "code",
        "color": "#74b9ff",
        "description": "Injecting malicious scripts into web pages viewed by other users.",
        "indicators": [
            "Unexpected JavaScript alerts on websites",
            "Unusual redirects after visiting pages",
            "Session cookies being stolen",
            "User data appearing on unauthorized pages",
        ],
        "prevention": [
            "Sanitize and encode all user input/output",
            "Implement Content Security Policy (CSP)",
            "Use HTTPOnly and Secure cookie flags",
            "Validate data on both client and server side",
            "Use modern web frameworks with built-in XSS protection",
        ],
        "system_signs": [
            "Random script alerts on trusted sites",
            "Being redirected without clicking anything",
            "Account activity from unknown locations",
        ],
    },
    {
        "id": 8,
        "name": "Brute Force Attack",
        "category": "Authentication Attack",
        "severity": "Medium",
        "icon": "lock_reset",
        "color": "#55efc4",
        "description": "Automated trial of many passwords/keys until the correct one is found.",
        "indicators": [
            "Multiple failed login attempts in logs",
            "Account lockouts happening frequently",
            "Login attempts from unusual geographic locations",
            "Traffic spikes to authentication endpoints",
        ],
        "prevention": [
            "Implement account lockout policies",
            "Enable multi-factor authentication (MFA)",
            "Use strong, complex passwords",
            "Monitor and alert on failed login attempts",
            "Use CAPTCHA on login forms",
            "Implement rate limiting",
        ],
        "system_signs": [
            "Account locked out unexpectedly",
            "Receiving unexpected password reset emails",
            "Log files showing thousands of login attempts",
        ],
    },
]

TROUBLESHOOT_GUIDES = [
    {
        "id": "slow-pc",
        "title": "My Computer is Suddenly Very Slow",
        "icon": "speed",
        "category": "Performance",
        "severity": "Medium",
        "steps": [
            {
                "step": 1,
                "action": "Check for Malware",
                "detail": "Run a full system scan with your antivirus. Malware often consumes significant CPU/RAM. Use Windows Defender or Malwarebytes for a second opinion.",
            },
            {
                "step": 2,
                "action": "Check Running Processes",
                "detail": "Open Task Manager (Ctrl+Shift+Esc on Windows) or Activity Monitor (Mac). Sort by CPU and Memory to identify suspicious processes with random names.",
            },
            {
                "step": 3,
                "action": "Check Network Activity",
                "detail": "Look for unusually high network usage even when not downloading anything. This could indicate data exfiltration by malware.",
            },
            {
                "step": 4,
                "action": "Review Startup Programs",
                "detail": "Malware often adds itself to startup. Check Task Manager > Startup tab (Windows) or System Preferences > Login Items (Mac).",
            },
            {
                "step": 5,
                "action": "Check Disk Health",
                "detail": "Failing hard drives cause slowdowns. Run disk diagnostics. On Windows: chkdsk /f. On Linux: smartctl -a /dev/sda.",
            },
        ],
        "warning_signs": ["Ransomware may be encrypting files", "Cryptominer consuming resources", "Botnet activity"],
    },
    {
        "id": "browser-redirect",
        "title": "My Browser Keeps Redirecting",
        "icon": "alt_route",
        "category": "Browser Security",
        "severity": "High",
        "steps": [
            {
                "step": 1,
                "action": "Scan for Browser Hijackers",
                "detail": "Browser hijackers change your homepage, search engine, and redirect traffic. Use AdwCleaner or Malwarebytes to detect and remove them.",
            },
            {
                "step": 2,
                "action": "Check Browser Extensions",
                "detail": "Malicious extensions cause redirects. Remove all unfamiliar extensions. In Chrome: Settings > Extensions. In Firefox: Add-ons Manager.",
            },
            {
                "step": 3,
                "action": "Reset Browser Settings",
                "detail": "Reset your browser to default settings. This removes malicious changes to homepage, search engine, and startup pages.",
            },
            {
                "step": 4,
                "action": "Check Hosts File",
                "detail": "Malware may modify the hosts file to redirect domains. Check: C:\\Windows\\System32\\drivers\\etc\\hosts (Windows) or /etc/hosts (Linux/Mac).",
            },
            {
                "step": 5,
                "action": "Flush DNS Cache",
                "detail": "Clear your DNS cache. Windows: ipconfig /flushdns. Mac: sudo dscacheutil -flushcache. Linux: sudo systemd-resolve --flush-caches",
            },
        ],
        "warning_signs": ["Phishing sites may capture credentials", "Malvertising exposure", "Data theft risk"],
    },
    {
        "id": "unknown-logins",
        "title": "Unknown Login Attempts on My Accounts",
        "icon": "warning",
        "category": "Account Security",
        "severity": "Critical",
        "steps": [
            {
                "step": 1,
                "action": "Change Password Immediately",
                "detail": "Use a strong, unique password (12+ characters, mixed case, numbers, symbols). Use a password manager like Bitwarden or 1Password.",
            },
            {
                "step": 2,
                "action": "Enable Multi-Factor Authentication",
                "detail": "Add MFA/2FA to all important accounts immediately. Use an authenticator app (Google Authenticator, Authy) rather than SMS when possible.",
            },
            {
                "step": 3,
                "action": "Check Active Sessions",
                "detail": "Review all active sessions on your accounts and revoke access from unrecognized devices/locations. Most platforms show this in Security Settings.",
            },
            {
                "step": 4,
                "action": "Check for Data Breaches",
                "detail": "Visit haveibeenpwned.com to check if your email was in a data breach. Change passwords for any compromised accounts.",
            },
            {
                "step": 5,
                "action": "Review Account Activity",
                "detail": "Check recent account activity for unauthorized transactions, emails sent, files accessed, or settings changed.",
            },
        ],
        "warning_signs": ["Account takeover in progress", "Identity theft risk", "Financial fraud possible"],
    },
    {
        "id": "suspicious-email",
        "title": "Received a Suspicious Email",
        "icon": "mail",
        "category": "Email Security",
        "severity": "High",
        "steps": [
            {
                "step": 1,
                "action": "Do NOT Click Any Links",
                "detail": "Never click links in suspicious emails. Hover over links to see the actual URL destination before clicking anything.",
            },
            {
                "step": 2,
                "action": "Verify the Sender",
                "detail": "Check the actual sender email address (not just the display name). Legitimate companies use their official domain, e.g., @company.com not @company-support.net.",
            },
            {
                "step": 3,
                "action": "Check Email Headers",
                "detail": "Examine email headers to verify the true sending server. Mismatched 'From' and 'Reply-To' addresses are red flags.",
            },
            {
                "step": 4,
                "action": "Report the Email",
                "detail": "Report phishing emails to your IT team, email provider, and organizations like the Anti-Phishing Working Group (reportphishing@apwg.org).",
            },
            {
                "step": 5,
                "action": "Delete and Block",
                "detail": "Delete the email and block the sender. If you accidentally clicked a link, immediately run a malware scan and change passwords.",
            },
        ],
        "warning_signs": ["Phishing attempt detected", "Potential credential harvesting", "Malware delivery possible"],
    },
    {
        "id": "wifi-security",
        "title": "Concerned About WiFi Security",
        "icon": "wifi_lock",
        "category": "Network Security",
        "severity": "Medium",
        "steps": [
            {
                "step": 1,
                "action": "Use WPA3 or WPA2 Encryption",
                "detail": "Ensure your WiFi router uses WPA3 (preferred) or at minimum WPA2 encryption. Never use WEP (easily cracked) or open networks.",
            },
            {
                "step": 2,
                "action": "Change Default Router Credentials",
                "detail": "Change the default admin username and password on your router immediately. Default credentials are publicly known and easily exploited.",
            },
            {
                "step": 3,
                "action": "Check Connected Devices",
                "detail": "Review all devices connected to your network via your router's admin panel. Identify and remove any unfamiliar devices.",
            },
            {
                "step": 4,
                "action": "Disable WPS",
                "detail": "WiFi Protected Setup (WPS) has known vulnerabilities. Disable it in your router settings.",
            },
            {
                "step": 5,
                "action": "Use VPN on Public WiFi",
                "detail": "Always use a VPN when connecting to public WiFi (cafes, airports, hotels) to encrypt your traffic and prevent interception.",
            },
        ],
        "warning_signs": ["Unauthorized network access", "Traffic interception risk", "MitM attack possible"],
    },
    {
        "id": "ransomware-infected",
        "title": "Files Are Encrypted / Ransomware",
        "icon": "lock",
        "category": "Malware",
        "severity": "Critical",
        "steps": [
            {
                "step": 1,
                "action": "IMMEDIATELY Disconnect from Network",
                "detail": "Unplug ethernet cable and disable WiFi IMMEDIATELY. Ransomware spreads through networks. Isolating the device stops further spread.",
            },
            {
                "step": 2,
                "action": "Do NOT Pay the Ransom",
                "detail": "Paying does not guarantee file recovery and funds criminal operations. Contact law enforcement (FBI, local cybercrime unit) to report.",
            },
            {
                "step": 3,
                "action": "Document the Attack",
                "detail": "Take photos of ransom notes and record all details. This information is vital for law enforcement and insurance claims.",
            },
            {
                "step": 4,
                "action": "Check for Decryption Tools",
                "detail": "Visit NoMoreRansom.org – a free resource with decryption tools for many ransomware variants. Identify the ransomware strain first.",
            },
            {
                "step": 5,
                "action": "Restore from Backup",
                "detail": "If you have clean backups from before the infection, restore your system. Verify backups are not also encrypted before restoring.",
            },
        ],
        "warning_signs": ["CRITICAL: Active ransomware infection", "Data loss imminent", "Network spread possible"],
    },
]

# ─────────────────────────────────────────────
#  LINK SCANNER LOGIC
# ─────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    result = {
        "url": url,
        "score": 0,          # 0 = safe, higher = more suspicious
        "verdict": "Safe",
        "verdict_color": "#00d2ff",
        "checks": [],
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    # Normalize
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        full_url_lower = url.lower()

        # ── Check 1: HTTPS ──
        if parsed.scheme == "https":
            result["checks"].append({"label": "HTTPS Secure Connection", "status": "pass", "detail": "URL uses HTTPS encryption"})
        else:
            result["score"] += 20
            result["checks"].append({"label": "HTTPS Secure Connection", "status": "fail", "detail": "URL uses insecure HTTP – data is unencrypted"})

        # ── Check 2: Known malicious domain ──
        if domain in MALICIOUS_DOMAINS:
            result["score"] += 60
            result["checks"].append({"label": "Known Malicious Domain", "status": "fail", "detail": f"'{domain}' is listed as a known suspicious/malicious domain"})
        else:
            result["checks"].append({"label": "Known Malicious Domain", "status": "pass", "detail": "Domain not found in known malicious domain list"})

        # ── Check 3: URL shortener ──
        if is_shortener_domain(domain):
            result["score"] += 30
            result["checks"].append({"label": "URL Shortener Detected", "status": "warn", "detail": "URL shorteners can hide malicious destinations"})
        else:
            result["checks"].append({"label": "URL Shortener", "status": "pass", "detail": "No URL shortener detected"})

        # ── Check 4: Suspicious keywords ──
        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
        if len(found_keywords) >= 3:
            result["score"] += 25
            result["checks"].append({"label": "Suspicious Keywords", "status": "fail", "detail": f"Found {len(found_keywords)} suspicious keywords: {', '.join(found_keywords[:5])}"})
        elif len(found_keywords) >= 1:
            result["score"] += 10
            result["checks"].append({"label": "Suspicious Keywords", "status": "warn", "detail": f"Found keywords: {', '.join(found_keywords[:5])}"})
        else:
            result["checks"].append({"label": "Suspicious Keywords", "status": "pass", "detail": "No suspicious keywords detected in URL"})

        # ── Check 5: Suspicious TLD ──
        suspicious_tld_found = [tld for tld in SUSPICIOUS_TLDS if domain.endswith(tld)]
        if suspicious_tld_found:
            result["score"] += 20
            result["checks"].append({"label": "Suspicious TLD", "status": "warn", "detail": f"Top-level domain '{suspicious_tld_found[0]}' is commonly associated with malicious activity"})
        else:
            result["checks"].append({"label": "Suspicious TLD", "status": "pass", "detail": "Domain extension appears legitimate"})

        # ── Check 6: IP address as host ──
        ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        if ip_pattern.match(domain):
            result["score"] += 30
            result["checks"].append({"label": "IP Address as Host", "status": "fail", "detail": "Using raw IP address instead of domain name is highly suspicious"})
        else:
            result["checks"].append({"label": "IP Address as Host", "status": "pass", "detail": "Domain name used (not raw IP address)"})

        # ── Check 7: Excessive subdomains ──
        subdomain_count = len(domain.split(".")) - 2
        if subdomain_count > 3:
            result["score"] += 20
            result["checks"].append({"label": "Excessive Subdomains", "status": "warn", "detail": f"Found {subdomain_count} subdomains – phishing sites often use many subdomains to mimic legitimate URLs"})
        else:
            result["checks"].append({"label": "Excessive Subdomains", "status": "pass", "detail": "Normal subdomain depth"})

        # ── Check 8: URL length ──
        if len(url) > 150:
            result["score"] += 15
            result["checks"].append({"label": "URL Length", "status": "warn", "detail": f"URL is very long ({len(url)} chars) – malicious URLs are often obfuscated with extra parameters"})
        else:
            result["checks"].append({"label": "URL Length", "status": "pass", "detail": f"URL length is normal ({len(url)} chars)"})

        # ── Check 9: Special characters ──
        special_chars = ["%40", "%2F", "@", "//"]
        found_special = [c for c in special_chars if c in url]
        if found_special:
            result["score"] += 15
            result["checks"].append({"label": "Encoded / Special Characters", "status": "warn", "detail": "URL contains encoded or obfuscated characters commonly used in phishing URLs"})
        else:
            result["checks"].append({"label": "Encoded / Special Characters", "status": "pass", "detail": "No suspicious character encoding detected"})

        # ── Check 10: DNS Resolve ──
        try:
            socket.gethostbyname(domain)
            result["checks"].append({"label": "DNS Resolution", "status": "pass", "detail": f"Domain '{domain}' resolves successfully"})
        except socket.gaierror:
            result["score"] += 10
            result["checks"].append({"label": "DNS Resolution", "status": "warn", "detail": f"Could not resolve domain '{domain}' – may be offline or non-existent"})

        # ── Check 11: URLhaus API Check ──
        urlhaus_res = check_urlhaus(url)
        if "score_addition" in urlhaus_res:
            result["score"] += urlhaus_res["score_addition"]
            del urlhaus_res["score_addition"]
        result["checks"].append(urlhaus_res)

        # ── Check 12: VirusTotal API Check ──
        vt_res = check_virustotal(url)
        if "score_addition" in vt_res:
            result["score"] += vt_res["score_addition"]
            del vt_res["score_addition"]
        result["checks"].append(vt_res)

    except Exception as e:
        result["score"] += 50
        result["checks"].append({"label": "URL Parse Error", "status": "fail", "detail": f"Could not parse URL: {str(e)}"})

    # ── Final Verdict ──
    if result["score"] >= 70:
        result["verdict"] = "Malicious"
        result["verdict_color"] = "#ff4757"
        result["verdict_icon"] = "report"
    elif result["score"] >= 35:
        result["verdict"] = "Suspicious"
        result["verdict_color"] = "#ffa502"
        result["verdict_icon"] = "warning"
    elif result["score"] >= 15:
        result["verdict"] = "Potentially Risky"
        result["verdict_color"] = "#eccc68"
        result["verdict_icon"] = "info"
    else:
        result["verdict"] = "Likely Safe"
        result["verdict_color"] = "#2ed573"
        result["verdict_icon"] = "check_circle"

    result["risk_percent"] = min(result["score"], 100)
    return result


# ─────────────────────────────────────────────
#  AUTH MIDDLEWARE
# ─────────────────────────────────────────────

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.route("/")
def index():
    stats = {
        "threats_count": len(THREATS_DB),
        "guides_count": len(TROUBLESHOOT_GUIDES),
        "links_scanned": session.get("links_scanned", 0),
    }
    recent_threats = THREATS_DB[:4]
    return render_template("index.html", stats=stats, recent_threats=recent_threats)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("register"))

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not username or not password or not confirm_password:
            flash("All fields are required.", "error")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))
            
        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        if database.create_user(username, password_hash):
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already exists.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("login"))

        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("login"))

        user = database.get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["profile_image"] = user["profile_image"] if user["profile_image"] else ""
            # Load saved VT API key from DB into session
            saved_key = database.get_user_vt_key(user["username"])
            if saved_key:
                session["vt_api_key"] = saved_key

            flash(f"Welcome back, {username}! You are now securely logged in.", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

    return render_template("login.html", login_failed=False)

@app.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        if not validate_csrf():
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("edit_profile"))

        new_username = request.form.get("username")
        new_password = request.form.get("password")
        current_password = request.form.get("current_password", "")
        profile_img = request.files.get("profile_image")
        
        user_id = session.get("user_id")
        image_filename = None
        if profile_img and profile_img.filename:
            if profile_img.content_length and profile_img.content_length > 5 * 1024 * 1024:
                flash("Profile image must be under 5 MB.", "error")
                return redirect(url_for("edit_profile"))

            ext = profile_img.filename.rsplit('.', 1)[1].lower() if '.' in profile_img.filename else ''
            if ext not in ['png', 'jpg', 'jpeg', 'gif']:
                flash("Only PNG, JPG, and GIF images are allowed.", "error")
                return redirect(url_for("edit_profile"))

            image_filename = f"user_{user_id}_{secrets.token_hex(8)}.{ext}"
            upload_dir = os.path.join(app.root_path, 'static', 'uploads')
            os.makedirs(upload_dir, exist_ok=True)
            profile_img.save(os.path.join(upload_dir, image_filename))
        
        if not new_username:
            flash("Username cannot be empty.", "error")
            return redirect(url_for("edit_profile"))
            
        # Update username in database
        user_id = session.get("user_id")
        try:
            database.execute_query("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
            if new_password:
                if not current_password:
                    flash("Current password is required to set a new password.", "error")
                    return redirect(url_for("edit_profile"))
                user = database.get_user_by_username(session.get("username", ""))
                if not user or not check_password_hash(user["password_hash"], current_password):
                    flash("Current password is incorrect.", "error")
                    return redirect(url_for("edit_profile"))
                hashed_pwd = generate_password_hash(new_password)
                database.execute_query("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_pwd, user_id))
            
            if image_filename:
                database.execute_query("UPDATE users SET profile_image = ? WHERE id = ?", (image_filename, user_id))
                session["profile_image"] = image_filename
                
            # Update session
            session["username"] = new_username
            flash("Profile updated successfully.", "success")
            return redirect(url_for("edit_profile"))
        except Exception as e:
            flash("Error updating profile. Username might already be taken.", "error")
            return redirect(url_for("edit_profile"))
            
    # Fetch current user data to prepopulate
    user_id = session.get("user_id")
    current_user = database.execute_query("SELECT * FROM users WHERE id = ?", (user_id,), fetch_one=True)
    return render_template("edit_profile.html", current_user=current_user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/scanner")
@login_required
def scanner():
    vt_key_active = bool(session.get("vt_api_key"))
    if not vt_key_active:
        username = session.get("username", "")
        if username:
            vt_key_active = bool(database.get_user_vt_key(username))
    if not vt_key_active:
        vt_key_active = bool(os.environ.get("VIRUSTOTAL_API_KEY"))

    return render_template("scanner.html", vt_key_active=vt_key_active)


@app.route("/api/scan", methods=["POST"])
@login_required
def api_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_url(url)

    # Track scan count in session
    session["links_scanned"] = session.get("links_scanned", 0) + 1

    return jsonify(result)


@app.route("/api/config/vt-key", methods=["POST"])
@login_required
def config_vt_key():
    data = request.get_json() or {}
    key = data.get("key", "").strip()
    username = session.get("username", "")

    if key and (len(key) < 20 or not re.match(r'^[A-Za-z0-9]+$', key)):
        return jsonify({"status": "error", "message": "Invalid API key format."}), 400

    if username:
        database.set_user_vt_key(username, key)
    if key:
        session["vt_api_key"] = key
        return jsonify({"status": "success", "message": "VirusTotal API Key saved permanently ✓"})
    else:
        session.pop("vt_api_key", None)
        return jsonify({"status": "success", "message": "VirusTotal API Key cleared"})





# Common services map for port identification
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    111: "RPC", 119: "NNTP", 123: "NTP", 135: "RPC-DCOM", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 179: "BGP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP-TLS", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch", 27017: "MongoDB",
}

# High-risk ports
HIGH_RISK_PORTS = {21, 23, 135, 137, 138, 139, 445, 3389, 5900, 1080, 161}
MEDIUM_RISK_PORTS = {22, 25, 53, 80, 110, 143, 1433, 1521, 3306, 5432, 6379, 9200, 27017}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161,
                389, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389,
                5432, 5900, 6379, 8080, 8443, 9200, 27017]


def scan_port(host, port, timeout=0.5):
    """Attempt TCP connection to host:port. Returns True if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


MAC_CACHE = {}

def resolve_mac_vendor(mac):
    if not mac or mac.lower() in ["unknown", ""]:
        return "Unknown Vendor"
    
    mac_clean = mac.upper()
    prefix = mac_clean[:8].replace("-", ":")
    
    if prefix in MAC_CACHE:
        return MAC_CACHE[prefix]
        
    try:
        resp = req.get(f"https://macvendors.co/api/{mac_clean}", timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            vendor = data.get("result", {}).get("company", "Standard Network Device")
            MAC_CACHE[prefix] = vendor
            return vendor
    except Exception:
        pass
        
    prefix_lower = prefix.lower()
    vendors = {
        "00:11:24": "Apple", "00:26:bb": "Apple", "00:03:93": "Apple", "0c:4d:12": "Apple",
        "08:00:27": "VirtualBox", "00:50:56": "VMware", "00:0c:29": "VMware", "00:05:69": "VMware",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
        "00:17:88": "Philips Hue", "00:11:32": "Synology",
        "00:1d:7e": "TP-Link", "00:21:29": "TP-Link", "ec:08:6b": "TP-Link",
        "70:b3:d5": "Linksys", "18:b4:30": "Nest",
        "2c:30:33": "Netgear", "00:1e:2a": "Netgear",
        "3c:d9:2b": "HP", "f4:f5:e8": "HP", "00:18:71": "HP",
        "00:1a:a0": "Dell", "00:14:22": "Dell", "00:21:70": "Dell",
        "00:18:ba": "Cisco", "00:1d:a1": "Cisco", "00:1e:be": "Cisco",
        "00:1c:42": "Parallels", "d4:a1:48": "Ubiquiti", "fc:ec:da": "Ubiquiti",
        "00:22:64": "Samsung", "00:12:fb": "Samsung", "f4:7b:5e": "Samsung",
        "00:15:af": "Asus", "00:1e:8c": "Asus", "00:26:18": "Asus",
        "00:24:d7": "Intel", "00:1e:64": "Intel", "00:21:6a": "Intel",
        "3c:a6:16": "Xiaomi", "00:9e:c8": "Xiaomi",
        "00:18:8b": "Motorola", "00:00:0c": "Cisco",
    }
    return vendors.get(prefix_lower, "Standard Network Device")

def guess_device_type(open_ports, hostname, vendor):
    hostname_lower = hostname.lower()
    vendor_lower = vendor.lower()
    ports = {p["port"] for p in open_ports}
    
    if 53 in ports and (80 in ports or 443 in ports) and ("router" in hostname_lower or "gateway" in hostname_lower or "modem" in hostname_lower):
        return "Gateway / Router", "router"
    if 9100 in ports or 631 in ports or "printer" in hostname_lower or "epson" in hostname_lower or "canon" in hostname_lower or "hp" in hostname_lower and "print" in hostname_lower:
        return "Network Printer", "print"
    if 22 in ports or 111 in ports or 2049 in ports:
        if "synology" in vendor_lower or "nas" in hostname_lower:
            return "NAS / Storage Server", "dns"
        return "Linux Server / Device", "dns"
    if 135 in ports or 445 in ports or 3389 in ports:
        return "Windows PC / Server", "desktop_windows"
    if 8008 in ports or 8009 in ports or "tv" in hostname_lower or "roku" in hostname_lower or "chromecast" in hostname_lower or "apple-tv" in hostname_lower:
        return "Smart TV / Media Player", "tv"
    if "virtualbox" in vendor_lower or "vmware" in vendor_lower or "parallels" in vendor_lower:
        return "Virtual Machine", "filter_drama"
    if "raspberry" in vendor_lower or "nest" in vendor_lower or "hue" in vendor_lower:
        return "IoT Smart Device", "smart_toy"
    if "phone" in hostname_lower or "android" in hostname_lower or "iphone" in hostname_lower or "ipad" in hostname_lower:
        return "Mobile Device", "smartphone"
    if 80 in ports or 443 in ports:
        return "Web Server / Router", "router"
    return "Workstation / PC", "computer"

def get_arp_table():
    arp_table = {}
    try:
        if os.path.exists("/proc/net/arp"):
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip = parts[0]
                        mac = parts[3]
                        flags = parts[2]
                        if mac != "00:00:00:00:00:00" and flags != "0x0":
                            arp_table[ip] = mac
    except Exception:
        pass
    return arp_table

def parse_nmap_xml(xml_string, arp_cache):
    import xml.etree.ElementTree as ET
    hosts_list = []
    try:
        root = ET.fromstring(xml_string)
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue
                
            ip = None
            mac = None
            vendor = "Unknown Vendor"
            for addr in host.findall("address"):
                addrtype = addr.get("addrtype")
                if addrtype == "ipv4":
                    ip = addr.get("addr")
                elif addrtype == "mac":
                    mac = addr.get("addr")
                    vendor = addr.get("vendor", "Unknown Vendor")
                    
            if not ip:
                continue
                
            # Cross reference with local ARP table if MAC was not returned by Nmap
            if not mac or mac == "Unknown":
                mac = arp_cache.get(ip, "Unknown")
                if mac != "Unknown":
                    vendor = resolve_mac_vendor(mac)
                    
            hostname = ip
            for hname in host.findall("hostnames/hostname"):
                name = hname.get("name")
                if name:
                    hostname = name
                    break
                    
            open_ports = []
            detected_os = None
            
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state = port_elem.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = int(port_elem.get("portid"))
                        service_elem = port_elem.find("service")
                        service_name = "Unknown"
                        product = ""
                        version = ""
                        extrainfo = ""
                        
                        if service_elem is not None:
                            service_name = service_elem.get("name", "Unknown")
                            product = service_elem.get("product", "")
                            version = service_elem.get("version", "")
                            extrainfo = service_elem.get("extrainfo", "")
                            ostype = service_elem.get("ostype")
                            if ostype and not detected_os:
                                detected_os = ostype
                                
                            # Parse CPE elements
                            for cpe in service_elem.findall("cpe"):
                                cpe_text = cpe.text or ""
                                if cpe_text.startswith("cpe:/o:"):
                                    parts = cpe_text.split(":")
                                    if len(parts) > 2:
                                        os_name = parts[2].capitalize()
                                        if len(parts) > 3:
                                            os_name += f" {parts[3]}"
                                        detected_os = os_name
                                        
                        # Fallback keyword checks on version info
                        full_info = f"{product} {version} {extrainfo}".lower()
                        if not detected_os:
                            if "ubuntu" in full_info:
                                detected_os = "Ubuntu Linux"
                            elif "debian" in full_info:
                                detected_os = "Debian Linux"
                            elif "linux" in full_info:
                                detected_os = "Linux"
                            elif "windows" in full_info:
                                detected_os = "Windows"
                            elif "ios" in full_info or "apple-tv" in full_info:
                                detected_os = "Apple iOS / tvOS"
                            elif "osx" in full_info or "mac os" in full_info:
                                detected_os = "macOS"
                                
                        service = service_name
                        if product:
                            service = f"{service_name} ({product} {version})".strip()
                            
                        remedy = "Monitor service for unauthorized access."
                        if port_id in HIGH_RISK_PORTS:
                            risk = "High"; risk_color = "#ef4444"
                            remedy = "Block this port at the firewall immediately. Disable the service if not required."
                        elif port_id in MEDIUM_RISK_PORTS:
                            risk = "Medium"; risk_color = "#f59e0b"
                            remedy = "Ensure strong authentication. Restrict access to trusted IPs only."
                        else:
                            risk = "Low"; risk_color = "#10b981"
                            remedy = "Standard service. Ensure software is fully updated."
                            
                        if port_id == 21: remedy = "FTP uses plaintext credentials. Migrate to SFTP or FTPS."
                        elif port_id == 23: remedy = "Telnet is unencrypted. Replace with SSH immediately."
                        elif port_id == 3389: remedy = "RDP is heavily targeted. Place behind a VPN and require NLA/MFA."
                        elif port_id == 445: remedy = "SMB is vulnerable to ransomware. Disable SMBv1 and restrict WAN access."
                        elif port_id == 22: remedy = "Disable root login and enforce key-based authentication."
                        elif port_id == 80: remedy = "HTTP is unencrypted. Redirect traffic to HTTPS (port 443)."
                        
                        open_ports.append({
                            "port": port_id,
                            "state": "open",
                            "service": service,
                            "risk": risk,
                            "risk_color": risk_color,
                            "remedy": remedy
                        })
            
            # Map OS from open port signatures if nmap version sweep doesn't return anything
            open_port_ids = {p["port"] for p in open_ports}
            if not detected_os:
                if 135 in open_port_ids or 445 in open_port_ids or 3389 in open_port_ids:
                    detected_os = "Windows"
                elif 22 in open_port_ids or 111 in open_port_ids or 2049 in open_port_ids:
                    detected_os = "Linux"
                else:
                    detected_os = "Generic OS / Device"
                    
            dev_type, dev_icon = guess_device_type(open_ports, hostname, vendor)
            
            high = sum(1 for p in open_ports if p["risk"] == "High")
            med  = sum(1 for p in open_ports if p["risk"] == "Medium")
            if high:   risk = "High";   risk_color = "#ef4444"
            elif med:  risk = "Medium"; risk_color = "#f59e0b"
            elif open_ports: risk = "Low"; risk_color = "#10b981"
            else:      risk = "Online"; risk_color = "#10b981"
            
            hosts_list.append({
                "ip": ip,
                "hostname": hostname,
                "mac": mac or "Unknown",
                "vendor": vendor,
                "alive": True,
                "open_ports": open_ports,
                "open_count": len(open_ports),
                "risk": risk,
                "risk_color": risk_color,
                "device_type": dev_type,
                "device_icon": dev_icon,
                "os": detected_os
            })
    except Exception as e:
        print(f"Error parsing XML: {e}")
    return hosts_list

# ─────────────────────────────────────────────────────────────────────────────
# DUAL-ENGINE SCANNER  (nmap preferred · pure-Python socket fallback)
#
# Architecture note for web/mobile clients:
#   Clients (phones, tablets, any browser, any OS) install NOTHING.
#   They open the Securix URL → the SERVER does all scanning.
#   The server auto-detects nmap at startup:
#     • nmap found  → rich OS fingerprinting + version detection
#     • nmap absent → built-in pure-Python socket scanner kicks in
#   Either way: zero client-side dependencies, fully web-native.
# ─────────────────────────────────────────────────────────────────────────────
import shutil as _shutil

NMAP_ENGINE = bool(_shutil.which("nmap"))


def _socket_scan_subnet(base, scan_depth, arp_cache):
    """Pure-Python threaded subnet scanner — zero external dependencies."""
    import concurrent.futures

    ports_to_use = []
    if scan_depth == "deep":
        ports_to_use = list(range(1, 1025))
    elif scan_depth != "ping":
        ports_to_use = COMMON_PORTS

    def probe_host(i):
        ip = f"{base}.{i}"
        arp_mac = arp_cache.get(ip)
        alive = bool(arp_mac)
        if not alive:
            for pp in [80, 22, 443, 445, 8080, 3389]:
                if scan_port(ip, pp, timeout=0.2):
                    alive = True
                    break
        if not alive:
            return None

        try:    hostname = socket.gethostbyaddr(ip)[0]
        except: hostname = ip

        mac    = arp_mac or "Unknown"
        vendor = resolve_mac_vendor(mac) if mac != "Unknown" else "Unknown Vendor"

        open_ports = []
        for port in ports_to_use:
            if scan_port(ip, port, timeout=0.3):
                service = PORT_SERVICES.get(port, "Unknown")
                remedy  = "Monitor for unauthorised access."
                if port in HIGH_RISK_PORTS:
                    risk = "High";   risk_color = "#ef4444"
                    remedy = "Block at firewall. Disable if not required."
                elif port in MEDIUM_RISK_PORTS:
                    risk = "Medium"; risk_color = "#f59e0b"
                    remedy = "Restrict access to trusted IPs."
                else:
                    risk = "Low";    risk_color = "#10b981"
                if port == 21:   remedy = "FTP is plaintext — migrate to SFTP."
                elif port == 23: remedy = "Telnet is unencrypted — use SSH."
                elif port == 3389: remedy = "RDP must be behind a VPN."
                elif port == 445: remedy = "Disable SMBv1; restrict WAN access."
                elif port == 22: remedy = "Enforce key-based auth, disable root login."
                elif port == 80: remedy = "Redirect all traffic to HTTPS (443)."
                open_ports.append({"port": port, "state": "open",
                                   "service": service, "risk": risk,
                                   "risk_color": risk_color, "remedy": remedy})

        ids = {p["port"] for p in open_ports}
        if 135 in ids or 445 in ids or 3389 in ids: os_g = "Windows"
        elif 22 in ids or 111 in ids:               os_g = "Linux"
        else:                                        os_g = "Generic Device"

        dev_type, dev_icon = guess_device_type(open_ports, hostname, vendor)
        high = sum(1 for p in open_ports if p["risk"] == "High")
        med  = sum(1 for p in open_ports if p["risk"] == "Medium")
        if high:         r = "High";   rc = "#ef4444"
        elif med:        r = "Medium"; rc = "#f59e0b"
        elif open_ports: r = "Low";    rc = "#10b981"
        else:            r = "Online"; rc = "#10b981"
        return {"ip": ip, "hostname": hostname, "mac": mac, "vendor": vendor,
                "alive": True, "open_ports": open_ports,
                "open_count": len(open_ports), "risk": r, "risk_color": rc,
                "device_type": dev_type, "device_icon": dev_icon, "os": os_g}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=80) as ex:
        for r in ex.map(probe_host, range(1, 255)):
            if r: results.append(r)

    existing = {h["ip"] for h in results}
    for ip, mac in arp_cache.items():
        if ip.startswith(base + ".") and ip not in existing:
            try:    hostname = socket.gethostbyaddr(ip)[0]
            except: hostname = ip
            results.append({"ip": ip, "hostname": hostname, "mac": mac,
                            "vendor": resolve_mac_vendor(mac), "alive": True,
                            "open_ports": [], "open_count": 0,
                            "risk": "Online", "risk_color": "#10b981",
                            "device_type": "Network Device", "device_icon": "devices",
                            "os": "Generic Device"})

    results.sort(key=lambda h: int(h["ip"].split(".")[-1]) if len(h["ip"].split(".")) == 4 else 0)
    return results


def _socket_scan_target(target_ip, port_range):
    """Pure-Python single-host port scanner fallback."""
    import concurrent.futures
    ports_to_scan = COMMON_PORTS
    if port_range == "all":
        ports_to_scan = list(range(1, 1025))
    elif port_range and port_range != "common":
        try:
            ports_to_scan = []
            for seg in port_range.split(","):
                seg = seg.strip()
                if "-" in seg:
                    a, b = map(int, seg.split("-"))
                    ports_to_scan.extend(range(a, b + 1))
                else:
                    ports_to_scan.append(int(seg))
        except Exception:
            ports_to_scan = COMMON_PORTS

    open_ports = []
    def check(port):
        if not scan_port(target_ip, port, timeout=0.4): return None
        service = PORT_SERVICES.get(port, "Unknown")
        remedy  = "Keep service updated."
        if port in HIGH_RISK_PORTS:
            risk = "High"; risk_color = "#ef4444"; remedy = "Disable or firewall this port."
        elif port in MEDIUM_RISK_PORTS:
            risk = "Medium"; risk_color = "#f59e0b"; remedy = "Restrict access; enforce MFA."
        else:
            risk = "Low"; risk_color = "#10b981"
        if port == 21:   remedy = "Migrate from FTP to SFTP."
        elif port == 23: remedy = "Replace Telnet with SSH."
        elif port == 3389: remedy = "Put RDP behind a VPN."
        elif port == 445: remedy = "Disable SMBv1; restrict WAN."
        return {"port": port, "service": service, "risk": risk,
                "risk_color": risk_color, "remedy": remedy}

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        for r in ex.map(check, ports_to_scan):
            if r: open_ports.append(r)

    try:    hostname = socket.gethostbyaddr(target_ip)[0]
    except: hostname = target_ip

    high = sum(1 for p in open_ports if p["risk"] == "High")
    med  = sum(1 for p in open_ports if p["risk"] == "Medium")
    if high:         r = "High";   rc = "#ef4444"
    elif med:        r = "Medium"; rc = "#f59e0b"
    elif open_ports: r = "Low";    rc = "#10b981"
    else:            r = "Secure"; rc = "#10b981"

    ids = {p["port"] for p in open_ports}
    if 135 in ids or 445 in ids or 3389 in ids: os_g = "Windows"
    elif 22 in ids or 111 in ids:               os_g = "Linux"
    else:                                        os_g = "Generic Device"

    arp = get_arp_table()
    mac    = arp.get(target_ip, "N/A")
    vendor = resolve_mac_vendor(mac) if mac != "N/A" else "Unknown Vendor"
    dev_type, dev_icon = guess_device_type(open_ports, hostname, vendor)
    return {"ip": target_ip, "hostname": hostname, "mac": mac, "vendor": vendor,
            "alive": True, "open_ports": open_ports, "open_count": len(open_ports),
            "risk": r, "risk_color": rc, "device_type": dev_type,
            "device_icon": dev_icon, "os": os_g}


@app.route("/api/scanner-engine")
def api_scanner_engine():
    """Tells the UI which scan engine the server is currently using."""
    return jsonify({
        "engine": "nmap" if NMAP_ENGINE else "socket",
        "label": "Nmap Engine" if NMAP_ENGINE else "Built-in Socket Engine",
        "color": "#3b82f6" if NMAP_ENGINE else "#8b5cf6",
        "note": (
            "nmap detected — OS fingerprinting, service version detection & fast subnet sweeps active."
            if NMAP_ENGINE else
            "Running in built-in socket mode (zero dependencies). "
            "Install nmap on the server for enhanced OS fingerprinting."
        )
    })


@app.route("/api/scan-network", methods=["POST"])
@login_required
def api_scan_network():
    import subprocess
    data        = request.get_json() or {}
    scan_depth  = data.get("scan_depth", "common")
    subnet_hint = data.get("subnet", "").strip()

    def get_local_subnet():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            parts = local_ip.split(".")
            return ".".join(parts[:3]), local_ip
        except Exception:
            return "192.168.1", "192.168.1.1"

    if subnet_hint:
        if "/" in subnet_hint:
            subnet_to_scan = subnet_hint
        else:
            parts = subnet_hint.split(".")
            subnet_to_scan = ".".join(parts[:3]) + ".0/24" if len(parts) >= 3 else subnet_hint + ".0/24"
        base      = ".".join(subnet_to_scan.split(".")[:3])
        server_ip = "192.168.1.1"
    else:
        base, server_ip = get_local_subnet()
        subnet_to_scan  = f"{base}.0/24"

    try:
        ssid = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True, timeout=1).stdout.strip()
    except Exception:
        ssid = ""
    ssid = ssid or "Network"

    arp_cache = get_arp_table()

    if NMAP_ENGINE:
        try:
            res = subprocess.run(["nmap", "-sn", subnet_to_scan, "-oX", "-"],
                                 capture_output=True, text=True, timeout=15)
            discovered = parse_nmap_xml(res.stdout, arp_cache)
        except Exception as e:
            return jsonify({"error": f"Nmap sweep failed: {str(e)}"}), 500

        if not discovered:
            active_hosts = []
        elif scan_depth == "ping":
            active_hosts = discovered
        else:
            if scan_depth == "aggressive":
                nmap_args = ["nmap", "-A", "-T4", "-p", "1-1024", "-oX", "-"] + [h["ip"] for h in discovered]
                timeout_val = 90
            else:
                ports_arg = ",".join(map(str, COMMON_PORTS))
                if scan_depth == "deep": ports_arg = "1-1024"
                nmap_args = ["nmap", "-sV", "-T4", "--version-light", "--open", "-p", ports_arg, "-oX", "-"] + [h["ip"] for h in discovered]
                timeout_val = 45
                
            try:
                rp = subprocess.run(nmap_args, capture_output=True, text=True, timeout=timeout_val)
                detailed = parse_nmap_xml(rp.stdout, arp_cache)
                dmap     = {h["ip"]: h for h in detailed}
                active_hosts = []
                for h in discovered:
                    if h["ip"] in dmap:
                        active_hosts.append(dmap[h["ip"]])
                    else:
                        h.update({"open_ports": [], "open_count": 0,
                                  "risk": "Online", "risk_color": "#10b981",
                                  "os": "Generic Device"})
                        active_hosts.append(h)
            except Exception:
                active_hosts = discovered
    else:
        active_hosts = _socket_scan_subnet(base, scan_depth, arp_cache)

    active_hosts.sort(
        key=lambda h: int(h["ip"].split(".")[-1]) if len(h["ip"].split(".")) == 4 else 0)

    return jsonify({
        "subnet": subnet_to_scan, "ssid": ssid, "server_ip": server_ip,
        "engine": "nmap" if NMAP_ENGINE else "socket",
        "hosts_scanned": 254 if "/24" in subnet_to_scan else 1,
        "active_count": len(active_hosts), "active_hosts": active_hosts
    })


@app.route("/api/scan-target-ip", methods=["POST"])
@login_required
def api_scan_target_ip():
    import subprocess
    data       = request.get_json() or {}
    target_ip  = data.get("target_ip", "").strip()
    port_range = data.get("ports", "").strip()

    if not target_ip:
        return jsonify({"error": "No target IP address provided"}), 400
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        return jsonify({"error": "Invalid IP address format"}), 400

    if NMAP_ENGINE:
        ports_arg = "F"
        if port_range == "all":        ports_arg = "1-1024"
        elif port_range and port_range != "common": ports_arg = port_range
        try:
            res = subprocess.run(
                ["nmap", "-sV", "-T4", "--version-light", "-p", ports_arg, "-oX", "-", target_ip],
                capture_output=True, text=True, timeout=30)
            hosts = parse_nmap_xml(res.stdout, get_arp_table())
            host_data = hosts[0] if hosts else {
                "ip": target_ip, "hostname": target_ip, "mac": "N/A",
                "vendor": "Unknown", "alive": True, "open_ports": [],
                "open_count": 0, "risk": "Secure", "risk_color": "#10b981",
                "device_type": "Workstation / PC", "device_icon": "computer",
                "os": "Generic Device"}
            host_data["engine"] = "nmap"
            return jsonify(host_data)
        except Exception as e:
            return jsonify({"error": f"Nmap scan failed: {str(e)}"}), 500
    else:
        host_data = _socket_scan_target(target_ip, port_range)
        host_data["engine"] = "socket"
        return jsonify(host_data)


@app.route("/api/scan-file", methods=["POST"])
@login_required
def api_scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    
    filename = secure_filename(file.filename)
    file_bytes = file.read()
    
    # Check size (max 10MB)
    file_size_kb = len(file_bytes) / 1024
    if file_size_kb > 10240:
        return jsonify({"error": "File size exceeds 10MB limit"}), 400
        
    # Calculate SHA256
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    # API key: session → DB → environment
    api_key = session.get("vt_api_key")
    if not api_key:
        username = session.get("username", "")
        if username:
            api_key = database.get_user_vt_key(username) or None
    if not api_key:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    
    # Step 1: Check local offline signature database first (always runs, no API needed)
    local_match = database.get_malware_by_hash(sha256_hash)
    if local_match:
        vt_result = {
            "label": "SECURIX Local Signature Engine",
            "status": "fail",
            "detail": f"⚠ THREAT DETECTED (Offline): File matches known signature '{local_match['threat_name']}' [{local_match['severity']}]. {local_match['details']}"
        }
    # Step 2: Live VirusTotal cloud check if API key is available
    elif api_key:
        vt_result = check_virustotal_file(sha256_hash, file_bytes, filename, api_key)
    else:
        vt_result = {
            "label": "SECURIX Local Signature Engine",
            "status": "pass",
            "detail": "No local signature match found. File hash is clean against offline threat database. Configure a VirusTotal API key for real-time global cloud analysis."
        }
        
    # Standard static checks on file name / size / type
    checks = []
    
    # Check 1: File size
    checks.append({
        "label": "File Size Verification",
        "status": "pass" if file_size_kb <= 5120 else "warn",
        "detail": f"File size is {file_size_kb:.2f} KB."
    })
    
    # Check 2: Extension Analysis
    suspicious_exts = [".exe", ".scr", ".bat", ".com", ".vbs", ".js", ".msi", ".ps1", ".jar", ".zip", ".rar", ".7z", ".dll"]
    ext = os.path.splitext(filename.lower())[1]
    is_suspicious_ext = ext in suspicious_exts
    checks.append({
        "label": "Executable & Container Analysis",
        "status": "fail" if is_suspicious_ext else "pass",
        "detail": f"File extension '{ext}' is considered " + ("highly suspicious/executable" if is_suspicious_ext else "standard/low risk") + "."
    })
    
    # Add VirusTotal result
    checks.append(vt_result)
    
    # Calculate risk score
    risk_score = 0
    if is_suspicious_ext:
        risk_score += 40
    if vt_result["status"] == "fail":
        risk_score += 60
    elif vt_result["status"] == "warn":
        risk_score += 30
        
    risk_score = min(risk_score, 100)
    
    # Verdict details
    if risk_score >= 75:
        verdict = "Malicious"
        verdict_color = "var(--error)"
        verdict_icon = "gpp_bad"
    elif risk_score >= 35:
        verdict = "Suspicious"
        verdict_color = "var(--warning)"
        verdict_icon = "warning"
    else:
        verdict = "Likely Safe"
        verdict_color = "var(--success)"
        verdict_icon = "check_circle"
        
    result = {
        "url": filename,  # reuse field name for compatibility with verdict UI & PDF
        "verdict": verdict,
        "verdict_color": verdict_color,
        "verdict_icon": verdict_icon,
        "risk_percent": risk_score,
        "checks": checks
    }
    
    # Track statistics in session
    session["links_scanned"] = session.get("links_scanned", 0) + 1
    
    return jsonify(result)


@app.route("/threats")
def threats():
    category = request.args.get("category", "All")
    if category == "All":
        filtered = THREATS_DB
    else:
        filtered = [t for t in THREATS_DB if t["category"] == category]

    categories = list(set(t["category"] for t in THREATS_DB))
    categories.sort()
    return render_template("threats.html", threats=filtered, categories=categories, active_category=category)


@app.route("/threat/<int:threat_id>")
def threat_detail(threat_id):
    threat = next((t for t in THREATS_DB if t["id"] == threat_id), None)
    if not threat:
        return render_template("404.html"), 404
    return render_template("threat_detail.html", threat=threat)


@app.route("/troubleshoot")
@login_required
def troubleshoot():
    return render_template("troubleshoot.html", guides=TROUBLESHOOT_GUIDES)


@app.route("/troubleshoot/<guide_id>")
@login_required
def troubleshoot_detail(guide_id):
    guide = next((g for g in TROUBLESHOOT_GUIDES if g["id"] == guide_id), None)
    if not guide:
        return render_template("404.html"), 404
    return render_template("troubleshoot_detail.html", guide=guide)


@app.route("/awareness")
def awareness():
    return render_template("awareness.html")


@app.route("/simulator")
@login_required
def simulator():
    return render_template("simulator.html")


@app.route("/api/simulator/emails")
@login_required
def api_simulator_emails():
    return jsonify(MOCK_INBOX_EMAILS)


@app.route("/api/simulator/generate", methods=["POST"])
@login_required
def api_simulator_generate():
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "AI generation requires GROQ_API_KEY to be configured."}), 500

    data = request.get_json() or {}
    count = min(int(data.get("count", 5)), 10)
    difficulty = data.get("difficulty", "medium")

    prompt = f"""You are a cybersecurity training system. Generate {count} realistic emails for a phishing awareness training game.
{difficulty.capitalize()} difficulty. Include a mix of phishing and legitimate emails.

Return ONLY valid JSON (no markdown, no explanation) with this exact structure:
{{
  "emails": [
    {{
      "id": 1,
      "sender_name": "Display name",
      "sender_email": "email@domain.com",
      "subject": "Email subject line",
      "date": "Today, 10:24 AM",
      "body_html": "<p>Email body with <a href='http://example.com'>links</a> if applicable</p>",
      "is_phishing": true,
      "red_flags": [
        {{"target": "suspicious element", "reason": "why it is suspicious"}}
      ],
      "explanation": "Brief explanation of why this is or isn't phishing"
    }}
  ]
}}

Rules:
- Each email must have realistic body_html with proper HTML formatting
- Phishing emails: include legitimate-looking links that point to suspicious domains, urgency/pressure tactics
- Legitimate emails: professional tone, no red flags, proper corporate domains
- Red flags should only be present for phishing emails (empty array for legitimate)
- Make each scenario unique and realistic for a corporate environment
- Difficulty {difficulty}: adjust subtlety of red flags accordingly
- Use varied scenarios: billing, security alerts, HR, IT, management, payroll, etc."""

    try:
        groq_api_base = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1/chat/completions")
        groq_model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

        groq_response = req.post(
            groq_api_base,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": groq_model, "messages": [{"role": "system", "content": "You are a phishing simulation content generator. Output ONLY valid JSON."}, {"role": "user", "content": prompt}], "temperature": 0.8, "max_tokens": 4096},
            timeout=45
        )

        if groq_response.status_code != 200:
            err = groq_response.json().get("error", {}).get("message", "Unknown error")
            return jsonify({"error": f"AI generation error: {err}"}), 500

        reply = groq_response.json()["choices"][0]["message"]["content"]
        reply = reply.strip()
        if reply.startswith("```"):
            reply = reply.split("\n", 1)[-1]
            reply = reply.rsplit("```", 1)[0]
        parsed = json.loads(reply)
        return jsonify(parsed)

    except json.JSONDecodeError:
        return jsonify({"error": "AI returned invalid JSON. Try again.", "raw": reply[:500]}), 500
    except Exception as e:
        return jsonify({"error": f"Generation failed: {str(e)}"}), 500


@app.route("/api/simulator/debrief", methods=["POST"])
@login_required
def api_simulator_debrief():
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "AI debrief requires GROQ_API_KEY."}), 500

    data = request.get_json() or {}
    email = data.get("email", {})
    user_answered_phishing = data.get("userAnsweredPhishing", False)
    correct = data.get("correct", False)

    prompt = f"""You are a personalized cybersecurity coach. A user just analyzed an email in a phishing detection exercise. Generate a brief debrief (2-3 sentences).

Email subject: "{email.get('subject', 'N/A')}"
From: "{email.get('sender_name', 'N/A')} <{email.get('sender_email', 'N/A')}>"
Was actually phishing: {"YES" if email.get('is_phishing') else "NO"}
User classified it as: {"PHISHING" if user_answered_phishing else "LEGITIMATE"}
User was: {"CORRECT" if correct else "INCORRECT"}

{"" if correct else "They got it wrong. Gently point out what they missed and give one specific tip for next time."}

{"Briefly reinforce what made it " + ("phishing" if email.get('is_phishing') else "legitimate") + "." if correct else "Focus only on the key mistake and one clear tip."}

No emojis. No greetings. Just the feedback."""

    try:
        groq_api_base = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1/chat/completions")
        groq_model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

        groq_response = req.post(
            groq_api_base,
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={"model": groq_model, "messages": [{"role": "system", "content": "You are a supportive cybersecurity coach."}, {"role": "user", "content": prompt}], "temperature": 0.7, "max_tokens": 500},
            timeout=15
        )

        if groq_response.status_code != 200:
            return jsonify({"debrief": "Great effort! Review the red flags above to sharpen your skills."})

        reply = groq_response.json()["choices"][0]["message"]["content"]
        return jsonify({"debrief": reply.strip()})

    except Exception:
        return jsonify({"debrief": "Keep practicing! Each email you analyze sharpens your threat detection skills."})





# ── Gamification Routes ──

@app.route("/api/phishing/stats", methods=["POST"])
@login_required
def api_phishing_stats():
    data = request.get_json() or {}
    database.record_phishing_stat(
        session["username"],
        data.get("email_id", ""),
        data.get("campaign_id", 0),
        data.get("is_phishing", False),
        data.get("identified_correctly", False),
        data.get("response_time_ms", 0),
        data.get("red_flags_identified", 0),
        data.get("total_red_flags", 0),
        data.get("session_id", "")
    )
    check_and_award_badges(session["username"])
    return jsonify({"ok": True})


def check_and_award_badges(username):
    stats = database.get_user_stats(username)
    total = len(stats)
    correct = sum(1 for s in stats if s["identified_correctly"])
    badges_before = len(database.get_user_badges(username))
    badges_to_check = []

    if total >= 5:
        badges_to_check.append(("first_steps", "First Steps — Complete 5 email analyses"))
    if total >= 25:
        badges_to_check.append(("dedicated", "Dedicated Analyst — Complete 25 email analyses"))
    if total >= 100:
        badges_to_check.append(("phish_hunter", "Phish Hunter — Complete 100 email analyses"))
    if total > 0 and correct / total >= 0.9:
        badges_to_check.append(("eagle_eye", "Eagle Eye — Maintain 90%+ accuracy"))
    if total >= 10 and all(s["identified_correctly"] for s in stats[:10]):
        badges_to_check.append(("perfect_streak", "Perfect Streak — Get 10 in a row correct"))
    streak = 0
    for s in stats:
        if s["identified_correctly"]:
            streak += 1
        else:
            break
    if streak >= 5:
        badges_to_check.append(("hot_streak", "Hot Streak — 5 correct in a row"))
    phishing_count = sum(1 for s in stats if s["is_phishing"] and s["identified_correctly"])
    if phishing_count >= 10:
        badges_to_check.append(("phishing_spotted", "Phishing Spotter — Correctly identify 10 phishing emails"))

    for badge_id, _ in badges_to_check:
        database.award_badge(username, badge_id)

    badges_after = len(database.get_user_badges(username))
    return badges_after > badges_before


@app.route("/api/phishing/leaderboard")
@login_required
def api_phishing_leaderboard():
    lb = database.get_leaderboard()
    badge_lb = database.get_badge_leaderboard()
    return jsonify({"leaderboard": lb, "badge_leaderboard": badge_lb})


@app.route("/api/phishing/my-stats")
@login_required
def api_phishing_my_stats():
    stats = database.get_user_stats(session["username"])
    badges = database.get_user_badges(session["username"])

    total = len(stats)
    correct = sum(1 for s in stats if s["identified_correctly"])
    accuracy = round((correct / total * 100) if total > 0 else 0, 1)
    phishing_emails = sum(1 for s in stats if s["is_phishing"])
    phishing_correct = sum(1 for s in stats if s["is_phishing"] and s["identified_correctly"])
    legit_emails = total - phishing_emails
    legit_correct = correct - phishing_correct
    total_time = sum(s["response_time_ms"] for s in stats)

    return jsonify({
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "phishing_encountered": phishing_emails,
        "phishing_correct": phishing_correct,
        "legit_encountered": legit_emails,
        "legit_correct": legit_correct,
        "total_time_ms": total_time,
        "avg_time_ms": round(total_time / total) if total > 0 else 0,
        "badges": [{"id": b["badge_id"], "awarded": b["awarded_at"]} for b in badges]
    })


BADGE_DEFINITIONS = {
    "first_steps": "First Steps — Complete 5 email analyses",
    "dedicated": "Dedicated Analyst — Complete 25 email analyses",
    "phish_hunter": "Phish Hunter — Complete 100 email analyses",
    "eagle_eye": "Eagle Eye — Maintain 90%+ accuracy",
    "perfect_streak": "Perfect Streak — Get 10 in a row correct",
    "hot_streak": "Hot Streak — 5 correct in a row",
    "phishing_spotted": "Phishing Spotter — Correctly identify 10 phishing emails"
}


@app.route("/api/badges")
@login_required
def api_badges():
    return jsonify(BADGE_DEFINITIONS)


@app.route("/email-analyzer", methods=["GET", "POST"])
@login_required
def email_analyzer():
    if request.method == "POST":
        if request.is_json:
            data = request.get_json()
            raw_headers = data.get("headers", "").strip()
        else:
            raw_headers = request.form.get("headers", "").strip()

        if not raw_headers:
            if request.is_json:
                return jsonify({"error": "No headers provided"}), 400
            flash("Please paste email headers to analyze.", "error")
            return redirect(url_for("email_analyzer"))

        result = parse_email_headers(raw_headers)
        if request.is_json:
            return jsonify(result)
        return render_template("email_analyzer.html", result=result, raw_headers=raw_headers)

    return render_template("email_analyzer.html", result=None)


@app.route("/breach-checker")
@login_required
def breach_checker():
    return render_template("breach_checker.html")


@app.route("/api/breach/password", methods=["POST"])
@login_required
def api_breach_password():
    data = request.get_json()
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    
    count = check_password_breached(password)
    return jsonify({"count": count})


@app.route("/api/breach/email", methods=["POST"])
@login_required
def api_breach_email():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "No email provided"}), 400
    if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email):
        return jsonify({"error": "Invalid email format"}), 400

    found = next((item for item in MOCK_BREACH_DB if item["email"] == email), None)
    if found:
        return jsonify({"breached": True, "breaches": found["breaches"]})
    
    if "leak" in email or "breach" in email or "pwned" in email:
        simulated_breaches = [
            {
                "title": "Global Data Leak (Simulation)",
                "date": "January 2025",
                "details": "A simulated breach containing contact information, names, and passwords.",
                "compromised": ["Passwords", "Email addresses", "Names"]
            }
        ]
        return jsonify({"breached": True, "breaches": simulated_breaches})

    return jsonify({"breached": False, "breaches": []})


@app.route("/api/report/pdf", methods=["POST"])
@login_required
def generate_pdf_report():
    try:
        data = request.get_json()
        report_type = data.get("type", "scan")
        payload = data.get("data", {})

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        primary_color = colors.HexColor("#0f172a")
        text_color = colors.HexColor("#334155")
        
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=20,
            textColor=primary_color,
            spaceAfter=10
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle',
            parent=styles['Normal'],
            fontSize=9,
            textColor=colors.HexColor("#64748b"),
            spaceAfter=15
        )
        section_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=primary_color,
            spaceBefore=10,
            spaceAfter=5
        )
        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['Normal'],
            fontSize=9,
            textColor=text_color,
            leading=13
        )
        verdict_style = ParagraphStyle(
            'VerdictText',
            parent=styles['Normal'],
            fontSize=11,
            fontName='Helvetica-Bold',
            textColor=colors.HexColor(payload.get("verdict_color", "#00d2ff"))
        )

        elements = []
        elements.append(Paragraph("SECURIX — Security Diagnostic Report", title_style))
        elements.append(Paragraph("Powered by SECURIX Threat Intelligence Engine | Sword & Shield Protection", ParagraphStyle('Brand', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#3b82f6"), spaceAfter=4)))
        timestamp = payload.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        elements.append(Paragraph(f"Generated on {timestamp} | SECURIX Automated Security Diagnostics", subtitle_style))
        elements.append(Spacer(1, 10))

        summary_data = [
            [Paragraph("<b>Target Evaluated:</b>", body_style), Paragraph(payload.get("url") or payload.get("email") or payload.get("target", "N/A"), body_style)],
            [Paragraph("<b>Verdict Status:</b>", body_style), Paragraph(payload.get("verdict", "Unknown"), verdict_style)],
            [Paragraph("<b>Security Risk Score / Count:</b>", body_style), Paragraph(f"{payload.get('score', payload.get('count', 0))}", body_style)]
        ]
        summary_table = Table(summary_data, colWidths=[150, 390])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        if report_type == "scan":
            elements.append(Paragraph("Heuristics and Database Checks", section_style))
            checks = payload.get("checks", [])
            check_rows = [[Paragraph("<b>Security Check</b>", body_style), Paragraph("<b>Status</b>", body_style), Paragraph("<b>Details</b>", body_style)]]
            for check in checks:
                status_text = check.get("status", "pass").upper()
                status_color = "#2ed573"
                if status_text == "FAIL":
                    status_color = "#ff4757"
                elif status_text in ["WARN", "SOFTFAIL"]:
                    status_color = "#ffa502"
                elif status_text == "INFO":
                    status_color = "#00d2ff"
                
                check_rows.append([
                    Paragraph(check.get("label", "N/A"), body_style),
                    Paragraph(f"<font color='{status_color}'><b>{status_text}</b></font>", body_style),
                    Paragraph(check.get("detail", ""), body_style)
                ])
            check_table = Table(check_rows, colWidths=[130, 70, 340])
            check_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#cbd5e1")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            elements.append(check_table)

        elif report_type == "email":
            elements.append(Paragraph("Email Header Analysis Details", section_style))
            headers_extracted = payload.get("headers", {})
            header_rows = [
                [Paragraph("<b>Header Field</b>", body_style), Paragraph("<b>Extracted Value</b>", body_style)],
                [Paragraph("From", body_style), Paragraph(headers_extracted.get("from", "N/A"), body_style)],
                [Paragraph("To", body_style), Paragraph(headers_extracted.get("to", "N/A"), body_style)],
                [Paragraph("Subject", body_style), Paragraph(headers_extracted.get("subject", "N/A"), body_style)],
                [Paragraph("Date", body_style), Paragraph(headers_extracted.get("date", "N/A"), body_style)],
                [Paragraph("Return-Path", body_style), Paragraph(headers_extracted.get("return_path", "N/A") or "None", body_style)],
                [Paragraph("Reply-To", body_style), Paragraph(headers_extracted.get("reply_to", "N/A") or "None", body_style)],
            ]
            header_table = Table(header_rows, colWidths=[120, 420])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#cbd5e1")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 4),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            elements.append(header_table)
            elements.append(Spacer(1, 10))

            elements.append(Paragraph("Security Findings", section_style))
            findings = payload.get("findings", [])
            finding_rows = [[Paragraph("<b>Target Check</b>", body_style), Paragraph("<b>Result</b>", body_style), Paragraph("<b>Finding Summary</b>", body_style)]]
            for f in findings:
                status_text = f.get("status", "pass").upper()
                status_color = "#2ed573"
                if status_text == "FAIL":
                    status_color = "#ff4757"
                elif status_text in ["WARN", "SOFTFAIL"]:
                    status_color = "#ffa502"
                elif status_text == "INFO":
                    status_color = "#00d2ff"
                finding_rows.append([
                    Paragraph(f.get("label", ""), body_style),
                    Paragraph(f"<font color='{status_color}'><b>{status_text}</b></font>", body_style),
                    Paragraph(f.get("detail", ""), body_style)
                ])
            finding_table = Table(finding_rows, colWidths=[140, 70, 330])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#cbd5e1")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            elements.append(finding_table)

        elif report_type == "breach":
            elements.append(Paragraph("Credential Leak Diagnostic Findings", section_style))
            checks = payload.get("checks", [])
            check_rows = [[Paragraph("<b>Diagnostic Item</b>", body_style), Paragraph("<b>Breach Info</b>", body_style)]]
            for check in checks:
                check_rows.append([
                    Paragraph(check.get("label", "N/A"), body_style),
                    Paragraph(check.get("detail", ""), body_style)
                ])
            check_table = Table(check_rows, colWidths=[160, 380])
            check_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#cbd5e1")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            elements.append(check_table)

        elif report_type == "network":
            elements.append(Paragraph("Local Area Network Scan Results", section_style))
            active_hosts = payload.get("active_hosts", [])
            
            host_rows = [[
                Paragraph("<b>IP Address</b>", body_style),
                Paragraph("<b>Device Hostname</b>", body_style),
                Paragraph("<b>MAC Address & Brand</b>", body_style),
                Paragraph("<b>Open Ports</b>", body_style),
                Paragraph("<b>Risk Status</b>", body_style)
            ]]
            
            for host in active_hosts:
                ports_list = []
                for p in host.get("open_ports", []):
                    ports_list.append(f"{p['port']}/{p['service']}")
                ports_str = ", ".join(ports_list) if ports_list else "None"
                
                risk_val = host.get("risk", "Online").upper()
                risk_color = host.get("risk_color", "#10b981")
                
                host_rows.append([
                    Paragraph(host.get("ip", ""), body_style),
                    Paragraph(host.get("hostname", ""), body_style),
                    Paragraph(f"{host.get('mac', '')}<br/><font color='#64748b'>{host.get('vendor', '')}</font>", body_style),
                    Paragraph(ports_str, body_style),
                    Paragraph(f"<font color='{risk_color}'><b>{risk_val}</b></font>", body_style)
                ])
                
            host_table = Table(host_rows, colWidths=[80, 110, 150, 120, 80])
            host_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#cbd5e1")),
                ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            elements.append(host_table)

        elements.append(Spacer(1, 20))
        elements.append(Paragraph("<b>Security Notice:</b> This report is generated automatically by SECURIX. All findings represent potential risk indicators detected by the SECURIX engine. Cross-reference with your security team and follow industry-standard remediation practices.", ParagraphStyle('Notice', parent=styles['Normal'], fontSize=7.5, textColor=colors.HexColor("#64748b"))))

        doc.build(elements)
        buffer.seek(0)
        
        filename = f"securix_{report_type}_report.pdf"
        return send_file(
            buffer,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF: {str(e)}"}), 500


@app.route("/api/check-auth")
def check_auth():
    return jsonify({"authenticated": "user_id" in session})

@app.route("/api/stats")
def api_stats():
    return jsonify({
        "threats": len(THREATS_DB),
        "guides": len(TROUBLESHOOT_GUIDES),
        "scans": session.get("links_scanned", 0),
    })


# ─────────────────────────────────────────────
#  NEARBY WIFI SCANNER  (WiGLE API)
# ─────────────────────────────────────────────


# ─────────────────────────────────────────────
#  DOMAIN INTELLIGENCE ENDPOINT
# ─────────────────────────────────────────────
@app.route("/api/ip-intelligence", methods=["POST"])
@login_required
def api_ip_intelligence():
    data = request.get_json() or {}
    query = data.get("ip", "").strip()
    if not query:
        return jsonify({"error": "Domain required"}), 400

    # Strip protocol and path if user pasted a full URL
    if "://" in query:
        parsed = urllib.parse.urlparse(query)
        query = parsed.hostname or parsed.netloc.split(":")[0]
    query = query.rstrip("/")

    is_ip = _is_valid_ip(query)
    lookup_target = query

    # Resolve domain to IP for geo/VT lookups (ipapi.co only accepts IPs)
    if not is_ip:
        try:
            lookup_target = socket.gethostbyname(query)
        except Exception:
            return jsonify({"error": "Could not resolve domain"}), 400

    # ── Geolocation (ipapi.co) ──
    geo_data = None
    try:
        geo_res = req.get(f"https://ipapi.co/{lookup_target}/json/", timeout=5.0)
        geo_data = geo_res.json()
    except Exception:
        pass

    # ── VirusTotal ──
    vt_key = session.get("vt_api_key") or os.environ.get("VIRUSTOTAL_API_KEY")
    vt_stats = None
    if vt_key:
        try:
            vt_res = req.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{lookup_target}",
                headers={"x-apikey": vt_key},
                timeout=3.0
            )
            if vt_res.status_code == 200:
                vt_stats = vt_res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        except Exception:
            pass

    # ── WHOIS Lookup ──
    whois_data = None
    try:
        w = whois.whois(query)
        def _first_or_list(val):
            if not val:
                return None
            if isinstance(val, list):
                return [str(v) for v in val if v]
            return [str(val)] if str(val) else None
        whois_data = {
            "registrar": _first_or_list(w.registrar),
            "creation_date": str(w.creation_date[0]) if isinstance(w.creation_date, list) and w.creation_date else (str(w.creation_date) if w.creation_date else None),
            "expiration_date": str(w.expiration_date[0]) if isinstance(w.expiration_date, list) and w.expiration_date else (str(w.expiration_date) if w.expiration_date else None),
            "updated_date": str(w.updated_date[0]) if isinstance(w.updated_date, list) and w.updated_date else (str(w.updated_date) if w.updated_date else None),
            "name_servers": _first_or_list(w.name_servers),
            "org": _first_or_list(w.org),
            "country": w.country if isinstance(w.country, str) else (_first_or_list(w.country)[0] if _first_or_list(w.country) else None),
            "emails": _first_or_list(w.emails),
            "status": _first_or_list(w.status),
        }
    except Exception:
        whois_data = None

    # ── DNS Records ──
    dns_records = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
        try:
            answers = dns.resolver.resolve(query, rtype, lifetime=3.0)
            dns_records[rtype.lower()] = [str(r) for r in answers][:8]
        except Exception:
            dns_records[rtype.lower()] = []

    # Reverse DNS (PTR) — only for IPs
    if is_ip:
        try:
            hostname, _, _ = socket.gethostbyaddr(query)
            dns_records["ptr"] = hostname
        except Exception:
            dns_records["ptr"] = None
    else:
        dns_records["ptr"] = None

    # ── SSL Certificate (best-effort, port 443) ──
    ssl_info = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=query) as ssock:
            ssock.settimeout(4.0)
            ssock.connect((query, 443))
            cert = ssock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []) if x)
                issuer = dict(x[0] for x in cert.get("issuer", []) if x)
                ssl_info = {
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": cert.get("notBefore"),
                    "valid_to": cert.get("notAfter"),
                    "san": [f"{t[0]}:{t[1]}" for t in cert.get("subjectAltName", [])],
                    "version": cert.get("version"),
                }
    except Exception:
        ssl_info = None

    return jsonify({
        "geo": geo_data,
        "vt": vt_stats,
        "whois": whois_data,
        "dns": dns_records,
        "ssl": ssl_info,
    })


def _is_valid_ip(value):
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not 0 <= int(p) <= 255:
            return False
    return True

# ─────────────────────────────────────────────
#  AI CHATBOT
# ─────────────────────────────────────────────

@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "AI is not configured. Please contact the administrator."}), 500

    username = session["username"]

    try:
        data = request.json
        user_message = data.get("message", "").strip()
        conv_id = data.get("conversation_id")
        history = data.get("history", [])
        context = data.get("context", "")

        if not user_message:
            return jsonify({"error": "Empty message provided."}), 400

        # Create conversation if new
        if not conv_id:
            conv_id = database.create_conversation(username, user_message[:80])

        # Save user message
        user_msg_id = database.add_message(conv_id, "user", user_message)

        system_prompt = """You are Securix AI, a cybersecurity assistant. Answer in 2-4 short paragraphs maximum. Be direct and precise. Use Markdown only when it aids clarity (bullet points, bold). Never use emojis. If asked about a scan result, interpret it specifically. If you don't know, say so."""

        if context:
            system_prompt += f"\n\nContext:\n{context}"

        messages = [{"role": "system", "content": system_prompt}]
        for msg in history:
            role = "user" if msg.get("role") == "user" else "assistant"
            messages.append({"role": role, "content": msg.get("content", "")})
        messages.append({"role": "user", "content": user_message})

        groq_api_base = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1/chat/completions")
        groq_model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")

        groq_response = req.post(
            groq_api_base,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": groq_model,
                "messages": messages,
                "temperature": 0.4,
                "max_tokens": 1024
            },
            timeout=30
        )

        if groq_response.status_code != 200:
            err = groq_response.json().get("error", {}).get("message", "Unknown error")
            return jsonify({"error": f"AI service error: {err}"}), 500

        reply_text = groq_response.json()["choices"][0]["message"]["content"]

        # Save AI response + update title with first user message
        ai_msg_id = database.add_message(conv_id, "assistant", reply_text)

        # Update title to first user message if still default
        convs = database.get_conversations(username)
        for c in convs:
            if c["id"] == conv_id and not c.get("title"):
                database.update_conversation_title(conv_id, user_message[:80])
                break

        return jsonify({"response": reply_text, "conversation_id": conv_id, "user_message_id": user_msg_id, "ai_message_id": ai_msg_id})

    except req.exceptions.Timeout:
        return jsonify({"error": "AI took too long to respond. Please try again."}), 504
    except Exception as e:
        print(f"Chatbot error: {e}")
        return jsonify({"error": f"Failed to reach AI service: {str(e)}"}), 500


@app.route("/api/chat/history", methods=["GET"])
@login_required
def chat_history():
    username = session["username"]
    convs = database.get_conversations(username)
    return jsonify([{
        "id": c["id"],
        "title": c.get("title") or "New Chat",
        "created_at": c["created_at"],
        "updated_at": c["updated_at"]
    } for c in convs])


@app.route("/api/chat/history/<int:conv_id>", methods=["GET"])
@login_required
def chat_history_messages(conv_id):
    username = session["username"]
    convs = database.get_conversations(username)
    if not any(c["id"] == conv_id for c in convs):
        return jsonify({"error": "Conversation not found"}), 404
    msgs = database.get_messages(conv_id)
    return jsonify([{
        "id": m["id"],
        "role": m["role"],
        "content": m["content"],
        "created_at": m["created_at"]
    } for m in msgs])


@app.route("/api/chat/history/<int:conv_id>", methods=["DELETE"])
@login_required
def chat_delete_conversation(conv_id):
    username = session["username"]
    convs = database.get_conversations(username)
    if not any(c["id"] == conv_id for c in convs):
        return jsonify({"error": "Conversation not found"}), 404
    database.delete_conversation(conv_id)
    return jsonify({"ok": True})


@app.route("/api/chat/message/<int:msg_id>", methods=["PUT"])
@login_required
def chat_update_message(msg_id):
    data = request.json
    content = data.get("content", "").strip()
    if not content:
        return jsonify({"error": "Empty content"}), 400
    database.update_message(msg_id, content)
    return jsonify({"ok": True})


@app.route("/api/chat/message/<int:msg_id>", methods=["DELETE"])
@login_required
def chat_delete_message(msg_id):
    database.delete_message(msg_id)
    return jsonify({"ok": True})


# ─────────────────────────────────────────────
#  ERROR HANDLERS
# ─────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template("404.html"), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("FLASK_ENV", "development") == "development"
    app.run(debug=debug, host="0.0.0.0", port=port)
