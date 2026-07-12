import re
import urllib.parse
import logging
import phonenumbers
from phonenumbers import carrier, timezone as tz_module, geocoder, phonenumberutil
from flask import Blueprint, render_template, request, jsonify
import requests as req
from helpers import login_required, limiter

phone_bp = Blueprint("phone", __name__)

CALLTRACER_BASE = "https://calltracer.io/api/lookup"


def _generate_osint_urls(e164, national, country_iso, digits):
    """Generate OSINT and lookup URLs for a phone number."""
    encoded = urllib.parse.quote(e164)
    digits_only = re.sub(r"[^\d]", "", e164)
    google_query = urllib.parse.quote(f'"{e164}" OR "{national}"')

    return {
        "google": f"https://www.google.com/search?q={google_query}",
        "truecaller": f"https://www.truecaller.com/search/{country_iso.lower()}/{digits_only}",
        "whitepages": f"https://www.whitepages.com/phone/{digits_only}",
        "spokeo": f"https://www.spokeo.com/phone-lookup/{digits_only}",
        "beenverified": f"https://www.beenverified.com/phone/{digits_only}",
        "sync_me": f"https://sync.me/search/?number={encoded}",
        "calleridtest": f"https://www.calleridtest.com/results.php?phone={digits_only}",
        "shouldianswer": f"https://www.shouldianswer.com/phone-number/{digits_only}",
        "spamcalls": f"https://spamcalls.net/en/num/{digits_only}",
        "tellows": f"https://www.tellows.com/num/{digits_only}",
        "whocalledme": f"https://www.whocalledme.com/search/{digits_only}",
        "usphonebook": f"https://www.usphonebook.com/{digits_only}",
        "facebook": f"https://www.facebook.com/search/people/?q={encoded}",
        "linkedin": f"https://www.linkedin.com/search/results/all/?keywords={encoded}",
    }


def _check_messaging_apps(e164):
    """Generate WhatsApp and Telegram check links + detect patterns."""
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
        "osint_urls": {},
        "messaging_links": {},
        "spam_databases": {},
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

    result["osint_urls"] = _generate_osint_urls(
        result["e164"], result["national"], result["country_iso"], digits
    )
    result["messaging_links"] = _check_messaging_apps(result["e164"])
    result["spam_databases"] = _check_spam_databases(result["e164"], digits)

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

    spam_db = result.get("spam_databases", {})
    db_flagged = sum(1 for v in spam_db.values() if v in ("flagged", "negative"))
    if db_flagged >= 2:
        result["indicators"].append(f"Flagged on {db_flagged} spam databases")
    elif db_flagged == 1:
        result["indicators"].append("Flagged on at least one spam database")

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
        else:
            result["risk_level"] = "No Data"
            result["risk_color"] = "#6b7280"
            result["indicators"].append("No spam reports available — cannot confirm safety")

    return result


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
