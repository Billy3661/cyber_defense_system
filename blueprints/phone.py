import re
import logging
import phonenumbers
from phonenumbers import carrier, timezone as tz_module, geocoder, phonenumberutil
from flask import Blueprint, render_template, request, jsonify
import requests as req
from helpers import login_required, limiter

phone_bp = Blueprint("phone", __name__)

CALLTRACER_BASE = "https://calltracer.io/api/lookup"


def parse_and_enrich(raw_number):
    """Parse a phone number with phonenumbers lib and enrich with CallTracer spam data."""
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

    try:
        resp = req.get(f"{CALLTRACER_BASE}/{result['e164'].lstrip('+')}", timeout=8)
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
