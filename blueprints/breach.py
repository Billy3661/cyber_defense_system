import re
import os
from io import BytesIO
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, flash, send_file
import requests as req
import database
from helpers import login_required, check_password_breached, parse_email_headers, HIBP_API_KEY, limiter
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

breach_bp = Blueprint("breach", __name__)


@breach_bp.route("/email-analyzer", methods=["GET", "POST"])
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
            return redirect(url_for("breach.email_analyzer"))

        result = parse_email_headers(raw_headers)
        if request.is_json:
            return jsonify(result)
        return render_template("email_analyzer.html", result=result, raw_headers=raw_headers)

    return render_template("email_analyzer.html", result=None)


@breach_bp.route("/breach-checker")
@login_required
def breach_checker():
    return render_template("breach_checker.html")


@breach_bp.route("/api/breach/password", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def api_breach_password():
    data = request.get_json()
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400
    
    count = check_password_breached(password)
    return jsonify({"count": count})


@breach_bp.route("/api/breach/email", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_breach_email():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    if not email:
        return jsonify({"error": "No email provided"}), 400
    if not re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", email):
        return jsonify({"error": "Invalid email format"}), 400

    if not HIBP_API_KEY:
        return jsonify({
            "breached": False,
            "breaches": [],
            "info": "HIBP API key not configured. Email breach checking requires a HaveIBeenPwned API key. Get one at https://haveibeenpwned.com/API/Key"
        })

    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false&includeUnverified=true"
        headers = {
            "hibp-api-key": HIBP_API_KEY,
            "User-Agent": "Securix-CyberDefense-System"
        }
        resp = req.get(url, headers=headers, timeout=5.0)

        if resp.status_code == 200:
            breach_data = resp.json()
            breaches = []
            for b in breach_data:
                breaches.append({
                    "title": b.get("Name", "Unknown Breach"),
                    "date": b.get("BreachDate", "Unknown"),
                    "details": b.get("Description", "No details available."),
                    "compromised": b.get("DataClasses", [])
                })
            return jsonify({"breached": True, "breaches": breaches})
        elif resp.status_code == 404:
            return jsonify({"breached": False, "breaches": []})
        elif resp.status_code == 401:
            return jsonify({"error": "Invalid HIBP API key. Check your HIBP_API_KEY environment variable."}), 403
        elif resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "60")
            return jsonify({"error": f"Rate limited by HIBP. Try again in {retry_after} seconds."}), 429
        else:
            return jsonify({"error": f"HIBP API returned status {resp.status_code}."}), 502
    except req.exceptions.Timeout:
        return jsonify({"error": "HIBP API request timed out."}), 504
    except Exception as e:
        return jsonify({"error": f"Breach lookup failed: {str(e)}"}), 500


@breach_bp.route("/api/report/pdf", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def generate_pdf_report():
    try:
        data = request.get_json()
        report_type = data.get("type", "scan")
        payload = data.get("data", {})

        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer, pagesize=letter, rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )

        styles = getSampleStyleSheet()
        primary_color = colors.HexColor("#0f172a")
        text_color = colors.HexColor("#334155")
        
        title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=20, textColor=primary_color, spaceAfter=10)
        subtitle_style = ParagraphStyle('ReportSubtitle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=15)
        section_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=13, textColor=primary_color, spaceBefore=10, spaceAfter=5)
        body_style = ParagraphStyle('ReportBody', parent=styles['Normal'], fontSize=9, textColor=text_color, leading=13)
        verdict_style = ParagraphStyle('VerdictText', parent=styles['Normal'], fontSize=11, fontName='Helvetica-Bold', textColor=colors.HexColor(payload.get("verdict_color", "#00d2ff")))

        elements = []
        elements.append(Paragraph("SECURIX \u2014 Security Diagnostic Report", title_style))
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
                if status_text == "FAIL": status_color = "#ff4757"
                elif status_text in ["WARN", "SOFTFAIL"]: status_color = "#ffa502"
                elif status_text == "INFO": status_color = "#00d2ff"
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
                if status_text == "FAIL": status_color = "#ff4757"
                elif status_text in ["WARN", "SOFTFAIL"]: status_color = "#ffa502"
                elif status_text == "INFO": status_color = "#00d2ff"
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
            buffer, mimetype="application/pdf", as_attachment=True, download_name=filename
        )
    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF: {str(e)}"}), 500
