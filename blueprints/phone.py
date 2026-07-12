import re
import os
import logging
from datetime import datetime
from io import BytesIO
import phonenumbers
from phonenumbers import carrier, timezone as tz_module, geocoder, phonenumberutil
from flask import Blueprint, render_template, request, jsonify, send_file
import requests as req
from helpers import login_required, limiter, HIBP_API_KEY
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

phone_bp = Blueprint("phone", __name__)

CALLTRACER_BASE = "https://calltracer.io/api/lookup"
NUMLOOKUP_BASE = "https://api.numlookupapi.com/v1/validate"
NUMLOOKUP_KEY = os.environ.get("NUMLOOKUP_API_KEY", "")


def _check_messaging_apps(e164):
    """Generate WhatsApp and Telegram check links."""
    digits_only = re.sub(r"[^\d]", "", e164)
    return {
        "whatsapp_link": f"https://wa.me/{digits_only}",
        "telegram_link": f"https://t.me/+{digits_only}",
    }


def _check_spam_databases(e164, digits):
    """Cross-reference against spam databases via page scraping."""
    results = {}

    try:
        resp = req.get(
            f"https://spamcalls.net/en/num/{digits}",
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            text = resp.text
            if "Probably Spam" in text or "spam" in text.lower():
                results["spamcalls_status"] = "flagged"
            elif "No user reports" in text or "no reports" in text.lower():
                results["spamcalls_status"] = "clean"
            else:
                results["spamcalls_status"] = "unknown"
            import re as _re
            report_match = _re.search(r"(\d+)\s*(?:user\s*)?report", text, _re.IGNORECASE)
            if report_match:
                results["spamcalls_reports"] = int(report_match.group(1))
    except Exception as e:
        logging.debug("SpamCalls lookup failed: %s", e)
        results["spamcalls_status"] = "unavailable"

    try:
        resp = req.get(
            f"https://www.shouldianswer.com/phone-number/{digits}",
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            text = resp.text
            if "NEGATIVE" in text.upper() or "scam" in text.lower():
                results["shouldianswer_status"] = "negative"
            elif "POSITIVE" in text.upper():
                results["shouldianswer_status"] = "positive"
            elif "no rating" in text.lower() or "no reviews" in text.lower():
                results["shouldianswer_status"] = "no_rating"
            else:
                results["shouldianswer_status"] = "neutral"
    except Exception as e:
        logging.debug("ShouldIAnswer lookup failed: %s", e)
        results["shouldianswer_status"] = "unavailable"

    try:
        resp = req.get(
            f"https://www.tellows.com/num/{digits}",
            timeout=6,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if resp.status_code == 200:
            text = resp.text
            import re as _re
            score_match = _re.search(r'score["\s:]*(\d+)', text, _re.IGNORECASE)
            if score_match:
                results["tellows_score"] = int(score_match.group(1))
            if "scam" in text.lower() or "fraud" in text.lower():
                results["tellows_status"] = "flagged"
            elif "safe" in text.lower() or "clean" in text.lower():
                results["tellows_status"] = "clean"
            else:
                results["tellows_status"] = "unknown"
    except Exception as e:
        logging.debug("Tellows lookup failed: %s", e)
        results["tellows_status"] = "unavailable"

    return results


def _numlookup_enrich(digits, country_iso):
    """Enrich phone data via NumLookup API (free tier: 100 req/month)."""
    if not NUMLOOKUP_KEY:
        return {}
    try:
        resp = req.get(
            NUMLOOKUP_BASE,
            params={"apikey": NUMLOOKUP_KEY, "number": digits},
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "carrier": data.get("carrier", ""),
                "line_type": data.get("line_type", ""),
                "location": data.get("location", ""),
                "valid": data.get("valid"),
                "is_prepaid": data.get("is_prepaid", False),
                "international_format": data.get("international_format", ""),
                "country_name": data.get("country_name", ""),
            }
    except Exception as e:
        logging.debug("NumLookup failed for %s: %s", digits, e)
    return {}


def _check_hibp_phone(e164):
    """Check if a phone number appears in known data breaches via HIBP."""
    if not HIBP_API_KEY:
        return {"available": False, "reason": "HIBP API key not configured"}
    try:
        resp = req.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{e164}",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "User-Agent": "Securix-CyberDefense",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            breaches = resp.json()
            return {
                "available": True,
                "breached": True,
                "breach_count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name", ""),
                        "title": b.get("Title", ""),
                        "domain": b.get("Domain", ""),
                        "date": b.get("BreachDate", ""),
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in breaches[:10]
                ],
            }
        elif resp.status_code == 404:
            return {"available": True, "breached": False, "breach_count": 0, "breaches": []}
        elif resp.status_code == 401:
            return {"available": False, "reason": "Invalid HIBP API key"}
        elif resp.status_code == 429:
            return {"available": False, "reason": "HIBP rate limit exceeded"}
        else:
            return {"available": False, "reason": f"HIBP returned status {resp.status_code}"}
    except Exception as e:
        logging.debug("HIBP phone lookup failed for %s: %s", e164, e)
        return {"available": False, "reason": "HIBP request failed"}


def parse_and_enrich(raw_number):
    """Parse a phone number with phonenumbers lib and enrich with all sources."""
    result = {
        "input": raw_number,
        "valid": False,
        "possible": False,
        "e164": "",
        "international": "",
        "national": "",
        "country_code": None,
        "country_iso": "",
        "country_name": "",
        "carrier": "",
        "line_type": "",
        "location": "",
        "timezones": [],
        "spam_score": None,
        "total_reports": 0,
        "last_reported": None,
        "risk_level": "Unknown",
        "risk_color": "#6b7280",
        "indicators": [],
        "messaging_links": {},
        "spam_databases": {},
        "numlookup": {},
        "hibp_phone": {},
    }

    cleaned = re.sub(r"[^\d+]", "", raw_number.strip())
    if not cleaned.startswith("+") and len(cleaned) > 8:
        cleaned = "+" + cleaned

    try:
        parsed = phonenumbers.parse(cleaned, None)
    except phonenumbers.NumberParseException:
        result["indicators"].append("Could not parse number — check format")
        return result

    result["valid"] = phonenumbers.is_valid_number(parsed)
    result["possible"] = phonenumbers.is_possible_number(parsed)
    result["e164"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    result["international"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    result["national"] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
    result["country_code"] = parsed.country_code
    result["country_iso"] = phonenumbers.region_code_for_number(parsed) or ""
    result["country_name"] = geocoder.description_for_number(parsed, "en") or ""

    carrier_name = carrier.name_for_number(parsed, "en") or ""
    result["carrier"] = carrier_name

    num_type = phonenumbers.number_type(parsed)
    type_map = {
        phonenumberutil.PhoneNumberType.FIXED_LINE: "Fixed Line",
        phonenumberutil.PhoneNumberType.MOBILE: "Mobile",
        phonenumberutil.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        phonenumberutil.PhoneNumberType.TOLL_FREE: "Toll-Free",
        phonenumberutil.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        phonenumberutil.PhoneNumberType.SHARED_COST: "Shared Cost",
        phonenumberutil.PhoneNumberType.VOIP: "VoIP",
        phonenumberutil.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        phonenumberutil.PhoneNumberType.PAGER: "Pager",
        phonenumberutil.PhoneNumberType.UAN: "UAN",
        phonenumberutil.PhoneNumberType.VOICEMAIL: "Voicemail",
        phonenumberutil.PhoneNumberType.UNKNOWN: "Unknown",
    }
    result["line_type"] = type_map.get(num_type, "Unknown")

    geo_desc = geocoder.description_for_number(parsed, "en") or ""
    result["location"] = geo_desc if geo_desc else result["country_name"]

    tzs = list(tz_module.time_zones_for_number(parsed))
    result["timezones"] = tzs

    digits = re.sub(r"[^\d]", "", result["e164"])

    result["messaging_links"] = _check_messaging_apps(result["e164"])
    result["spam_databases"] = _check_spam_databases(result["e164"], digits)

    numlookup_data = _numlookup_enrich(digits, result["country_iso"])
    if numlookup_data:
        result["numlookup"] = numlookup_data
        if numlookup_data.get("carrier") and not result["carrier"]:
            result["carrier"] = numlookup_data["carrier"]
        if numlookup_data.get("line_type") and result["line_type"] in ("Unknown", ""):
            result["line_type"] = numlookup_data["line_type"].title()
        if numlookup_data.get("location") and not result["location"]:
            result["location"] = numlookup_data["location"]

    result["hibp_phone"] = _check_hibp_phone(result["e164"])

    try:
        resp = req.get(f"{CALLTRACER_BASE}/{digits}", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            reports = data.get("reports", {})
            result["spam_score"] = reports.get("spam_score")
            result["total_reports"] = reports.get("total", 0)
            result["last_reported"] = reports.get("last_reported_at")
            if not result["carrier"] and data.get("carrier"):
                result["carrier"] = data["carrier"]
            if result["line_type"] in ("Unknown", "") and data.get("number_type"):
                result["line_type"] = data["number_type"]
        else:
            logging.debug("CallTracer returned %s for %s", resp.status_code, result["e164"])
    except Exception as e:
        logging.debug("CallTracer lookup failed for %s: %s", result["e164"], e)

    if not result["valid"]:
        result["indicators"].append("Number is not valid for its country")
    if not result["possible"]:
        result["indicators"].append("Number does not match expected length for region")

    if result["line_type"] == "VoIP":
        result["indicators"].append("VoIP number — commonly used by scammers")
    if result["line_type"] in ("Premium Rate", "Shared Cost"):
        result["indicators"].append("Premium/shared-cost number — may overcharge if called")
    if result["line_type"] == "Toll-Free":
        result["indicators"].append("Toll-free number — legitimate businesses often use these")

    if result["numlookup"].get("is_prepaid"):
        result["indicators"].append("Prepaid number — harder to trace owner")

    spam_db = result.get("spam_databases", {})
    db_flagged = sum(1 for v in spam_db.values() if v in ("flagged", "negative"))
    if db_flagged >= 2:
        result["indicators"].append(f"Flagged on {db_flagged} spam databases")
    elif db_flagged == 1:
        result["indicators"].append("Flagged on at least one spam database")

    hibp = result.get("hibp_phone", {})
    if hibp.get("breached"):
        result["indicators"].append(f"Found in {hibp['breach_count']} data breach{'es' if hibp['breach_count'] != 1 else ''}")

    if result["spam_score"] is not None:
        if result["spam_score"] >= 70:
            result["risk_level"] = "High Risk"
            result["risk_color"] = "#ef4444"
            result["indicators"].append(f"High spam score ({result['spam_score']}/100) — widely reported")
        elif result["spam_score"] >= 40:
            result["risk_level"] = "Medium Risk"
            result["risk_color"] = "#f97316"
            result["indicators"].append(f"Moderate spam score ({result['spam_score']}/100)")
        elif result["spam_score"] >= 10:
            result["risk_level"] = "Low Risk"
            result["risk_color"] = "#eab308"
            result["indicators"].append(f"Low spam score ({result['spam_score']}/100) — some reports")
        else:
            result["risk_level"] = "Clean"
            result["risk_color"] = "#22c55e"
            result["indicators"].append("No significant spam reports")
    else:
        if not result["valid"]:
            result["risk_level"] = "Invalid"
            result["risk_color"] = "#ef4444"
        elif any(ind.startswith("VoIP") for ind in result["indicators"]):
            result["risk_level"] = "Caution"
            result["risk_color"] = "#f97316"
        elif any(ind.startswith("Premium") for ind in result["indicators"]):
            result["risk_level"] = "Caution"
            result["risk_color"] = "#f97316"
        elif db_flagged >= 2:
            result["risk_level"] = "High Risk"
            result["risk_color"] = "#ef4444"
        elif db_flagged == 1:
            result["risk_level"] = "Caution"
            result["risk_color"] = "#f97316"
        elif hibp.get("breached"):
            result["risk_level"] = "Caution"
            result["risk_color"] = "#f97316"
        else:
            result["risk_level"] = "No Data"
            result["risk_color"] = "#6b7280"
            result["indicators"].append("No spam reports available — cannot confirm safety")

    return result


def _build_phone_pdf(result):
    """Generate a PDF intelligence report for a phone scan."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, rightMargin=36, leftMargin=36,
        topMargin=36, bottomMargin=36,
    )

    styles = getSampleStyleSheet()
    primary_color = colors.HexColor("#0f172a")
    text_color = colors.HexColor("#334155")

    title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=20, textColor=primary_color, spaceAfter=10)
    subtitle_style = ParagraphStyle('ReportSubtitle', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor("#64748b"), spaceAfter=15)
    section_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=13, textColor=primary_color, spaceBefore=10, spaceAfter=5)
    body_style = ParagraphStyle('ReportBody', parent=styles['Normal'], fontSize=9, textColor=text_color, leading=13)
    verdict_style = ParagraphStyle('VerdictText', parent=styles['Normal'], fontSize=11, fontName='Helvetica-Bold', textColor=colors.HexColor(result.get("risk_color", "#6b7280")))

    elements = []
    elements.append(Paragraph("SECURIX — Phone Intelligence Report", title_style))
    elements.append(Paragraph("Powered by SECURIX Threat Intelligence Engine | Sword & Shield Protection", ParagraphStyle('Brand', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor("#3b82f6"), spaceAfter=4)))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"Generated on {timestamp} | SECURIX Automated Phone Intelligence", subtitle_style))
    elements.append(Spacer(1, 10))

    summary_data = [
        [Paragraph("<b>Phone Number:</b>", body_style), Paragraph(result.get("e164", result.get("input", "N/A")), body_style)],
        [Paragraph("<b>Risk Verdict:</b>", body_style), Paragraph(result.get("risk_level", "Unknown"), verdict_style)],
        [Paragraph("<b>Country:</b>", body_style), Paragraph(f"{result.get('country_name', 'N/A')} ({result.get('country_iso', '')})", body_style)],
        [Paragraph("<b>Carrier:</b>", body_style), Paragraph(result.get("carrier", "Unknown"), body_style)],
        [Paragraph("<b>Line Type:</b>", body_style), Paragraph(result.get("line_type", "Unknown"), body_style)],
        [Paragraph("<b>Location:</b>", body_style), Paragraph(result.get("location", "N/A"), body_style)],
        [Paragraph("<b>Timezone(s):</b>", body_style), Paragraph(", ".join(result.get("timezones", [])) or "N/A", body_style)],
        [Paragraph("<b>Spam Score:</b>", body_style), Paragraph(f"{result['spam_score']}/100" if result.get("spam_score") is not None else "N/A", body_style)],
    ]
    summary_table = Table(summary_data, colWidths=[140, 400])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0, 0), (-1, -1), 6),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Security Indicators", section_style))
    indicators = result.get("indicators", [])
    if indicators:
        ind_rows = [[Paragraph("<b>#</b>", body_style), Paragraph("<b>Indicator</b>", body_style)]]
        for i, ind in enumerate(indicators, 1):
            ind_rows.append([Paragraph(str(i), body_style), Paragraph(ind, body_style)])
        ind_table = Table(ind_rows, colWidths=[40, 500])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#cbd5e1")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(ind_table)
    else:
        elements.append(Paragraph("No indicators detected.", body_style))
    elements.append(Spacer(1, 10))

    spam_db = result.get("spam_databases", {})
    if spam_db:
        elements.append(Paragraph("Spam Database Results", section_style))
        db_rows = [[Paragraph("<b>Database</b>", body_style), Paragraph("<b>Status</b>", body_style)]]
        db_names = {
            "spamcalls_status": "SpamCalls.net",
            "shouldianswer_status": "ShouldIAnswer",
            "tellows_status": "Tellows",
        }
        for key, name in db_names.items():
            status = spam_db.get(key, "N/A")
            if status in ("unavailable", None):
                continue
            status_color = "#ef4444" if status in ("flagged", "negative") else "#22c55e" if status in ("clean", "positive") else "#eab308"
            db_rows.append([
                Paragraph(name, body_style),
                Paragraph(f"<font color='{status_color}'><b>{status.title()}</b></font>", body_style),
            ])
        if len(db_rows) > 1:
            db_table = Table(db_rows, colWidths=[200, 340])
            db_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#cbd5e1")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            elements.append(db_table)
        elements.append(Spacer(1, 10))

    hibp = result.get("hibp_phone", {})
    if hibp.get("available") and hibp.get("breached"):
        elements.append(Paragraph("Data Breach Exposure (HIBP)", section_style))
        breaches = hibp.get("breaches", [])
        if breaches:
            br_rows = [[Paragraph("<b>Breach</b>", body_style), Paragraph("<b>Date</b>", body_style), Paragraph("<b>Data Exposed</b>", body_style)]]
            for b in breaches:
                data_classes = ", ".join(b.get("data_classes", [])[:4])
                br_rows.append([
                    Paragraph(b.get("title", b.get("name", "N/A")), body_style),
                    Paragraph(b.get("date", "N/A"), body_style),
                    Paragraph(data_classes, body_style),
                ])
            br_table = Table(br_rows, colWidths=[160, 100, 280])
            br_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#cbd5e1")),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(br_table)
        elements.append(Spacer(1, 10))

    numlookup = result.get("numlookup", {})
    if numlookup:
        elements.append(Paragraph("Carrier Enrichment (NumLookup)", section_style))
        nl_rows = [
            [Paragraph("<b>Field</b>", body_style), Paragraph("<b>Value</b>", body_style)],
            [Paragraph("Carrier", body_style), Paragraph(numlookup.get("carrier") or "N/A", body_style)],
            [Paragraph("Line Type", body_style), Paragraph(numlookup.get("line_type") or "N/A", body_style)],
            [Paragraph("Location", body_style), Paragraph(numlookup.get("location") or "N/A", body_style)],
            [Paragraph("Prepaid", body_style), Paragraph("Yes" if numlookup.get("is_prepaid") else "No", body_style)],
        ]
        nl_table = Table(nl_rows, colWidths=[140, 400])
        nl_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#cbd5e1")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(nl_table)
        elements.append(Spacer(1, 10))

    elements.append(Spacer(1, 20))
    elements.append(Paragraph("<b>Security Notice:</b> This report is generated automatically by SECURIX. All findings represent potential risk indicators detected by the SECURIX engine. Cross-reference with your security team and follow industry-standard remediation practices.", ParagraphStyle('Notice', parent=styles['Normal'], fontSize=7.5, textColor=colors.HexColor("#64748b"))))

    doc.build(elements)
    buffer.seek(0)
    return buffer


@phone_bp.route("/phone-intelligence")
@login_required
def phone_page():
    return render_template("phone.html")


@phone_bp.route("/api/scan-phone", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def api_scan_phone():
    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or request.form.get("phone") or "").strip()
    if not phone:
        return jsonify({"error": "Phone number is required."}), 400

    result = parse_and_enrich(phone)
    return jsonify(result)


@phone_bp.route("/api/phone-report/pdf", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def generate_phone_pdf():
    try:
        data = request.get_json(silent=True) or {}
        result = data.get("data") or data
        if not result.get("e164"):
            return jsonify({"error": "No scan data provided."}), 400

        buffer = _build_phone_pdf(result)
        filename = f"securix_phone_{result['e164'].lstrip('+')}.pdf"
        return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=filename)
    except Exception as e:
        logging.error("Phone PDF generation failed: %s", e)
        return jsonify({"error": f"Failed to generate PDF: {str(e)}"}), 500
