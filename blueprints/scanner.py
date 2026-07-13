import os
import re
import json
import socket
import hashlib
import subprocess
from flask import Blueprint, render_template, request, jsonify, session
from werkzeug.utils import secure_filename
import database
from helpers import (
    login_required, analyze_url, check_virustotal, check_virustotal_file,
    NMAP_ENGINE, COMMON_PORTS, HIGH_RISK_PORTS, MEDIUM_RISK_PORTS,
    PORT_SERVICES, get_arp_table, parse_nmap_xml, _socket_scan_subnet,
    _socket_scan_target, get_cloudflare_radar_raw, limiter,
)

scanner_bp = Blueprint("scanner", __name__)


@scanner_bp.route("/scanner")
@login_required
def scanner_page():
    vt_key_active = bool(session.get("vt_api_key"))
    if not vt_key_active:
        username = session.get("username", "")
        if username:
            vt_key_active = bool(database.get_user_vt_key(username))
    if not vt_key_active:
        vt_key_active = bool(os.environ.get("VIRUSTOTAL_API_KEY"))

    return render_template("scanner.html", vt_key_active=vt_key_active)


@scanner_bp.route("/api/scan-url", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_scan_url():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    result = analyze_url(url)
    session["links_scanned"] = session.get("links_scanned", 0) + 1
    return jsonify(result)


@scanner_bp.route("/api/scan", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_scan():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    result = analyze_url(url)
    session["links_scanned"] = session.get("links_scanned", 0) + 1
    return jsonify(result)


@scanner_bp.route("/api/config/vt-key", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
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
        return jsonify({"status": "success", "message": "VirusTotal API Key saved successfully"})
    else:
        session.pop("vt_api_key", None)
        return jsonify({"status": "success", "message": "VirusTotal API Key cleared"})


@scanner_bp.route("/api/scanner-engine")
def api_scanner_engine():
    return jsonify({
        "engine": "nmap" if NMAP_ENGINE else "socket",
        "label": "Nmap Engine" if NMAP_ENGINE else "Built-in Socket Engine",
        "color": "#3b82f6" if NMAP_ENGINE else "#8b5cf6",
        "note": (
            "nmap detected \u2014 OS fingerprinting, service version detection & fast subnet sweeps active."
            if NMAP_ENGINE else
            "Running in built-in socket mode (zero dependencies). "
            "Install nmap on the server for enhanced OS fingerprinting."
        )
    })


@scanner_bp.route("/api/scan-network", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def api_scan_network():
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


@scanner_bp.route("/api/scan-target-ip", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_scan_target_ip():
    from helpers import is_private_ip

    data       = request.get_json() or {}
    target_ip  = data.get("target_ip", "").strip()
    port_range = data.get("ports", "").strip()

    if not target_ip:
        return jsonify({"error": "No target IP address provided"}), 400
    try:
        socket.inet_aton(target_ip)
    except socket.error:
        return jsonify({"error": "Invalid IP address format"}), 400

    if is_private_ip(target_ip):
        return jsonify({"error": "Scanning private/internal IPs is not allowed"}), 403

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


@scanner_bp.route("/api/scan-file", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    
    filename = secure_filename(file.filename)
    file_bytes = file.read()
    
    file_size_kb = len(file_bytes) / 1024
    if file_size_kb > 10240:
        return jsonify({"error": "File size exceeds 10MB limit"}), 400
        
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    
    api_key = session.get("vt_api_key")
    if not api_key:
        username = session.get("username", "")
        if username:
            api_key = database.get_user_vt_key(username) or None
    if not api_key:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    
    local_match = database.get_malware_by_hash(sha256_hash)
    if local_match:
        vt_result = {
            "label": "SECURIX Local Signature Engine",
            "status": "fail",
            "detail": f"\u26a0 THREAT DETECTED (Offline): File matches known signature '{local_match['threat_name']}' [{local_match['severity']}]. {local_match['details']}"
        }
    elif api_key:
        vt_result = check_virustotal_file(sha256_hash, file_bytes, filename, api_key)
    else:
        vt_result = {
            "label": "SECURIX Local Signature Engine",
            "status": "pass",
            "detail": "No local signature match found. File hash is clean against offline threat database. Configure a VirusTotal API key for real-time global cloud analysis."
        }
        
    checks = []
    
    checks.append({
        "label": "File Size Verification",
        "status": "pass" if file_size_kb <= 5120 else "warn",
        "detail": f"File size is {file_size_kb:.2f} KB."
    })
    
    suspicious_exts = [".exe", ".scr", ".bat", ".com", ".vbs", ".js", ".msi", ".ps1", ".jar", ".zip", ".rar", ".7z", ".dll"]
    ext = os.path.splitext(filename.lower())[1]
    is_suspicious_ext = ext in suspicious_exts
    checks.append({
        "label": "Executable & Container Analysis",
        "status": "fail" if is_suspicious_ext else "pass",
        "detail": f"File extension '{ext}' is considered " + ("highly suspicious/executable" if is_suspicious_ext else "standard/low risk") + "."
    })
    
    checks.append(vt_result)
    
    risk_score = 0
    if is_suspicious_ext:
        risk_score += 40
    if vt_result["status"] == "fail":
        risk_score += 60
    elif vt_result["status"] == "warn":
        risk_score += 30
        
    risk_score = min(risk_score, 100)
    
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
        "url": filename,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "verdict_icon": verdict_icon,
        "risk_percent": risk_score,
        "checks": checks
    }
    
    session["links_scanned"] = session.get("links_scanned", 0) + 1
    return jsonify(result)


@scanner_bp.route("/api/ip-intelligence", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def api_ip_intelligence():
    import ssl
    import urllib.parse
    import whois as whois_lib
    import dns.resolver
    import requests as req

    data = request.get_json() or {}
    query = data.get("ip", "").strip()
    if not query:
        return jsonify({"error": "Domain required"}), 400

    if "://" in query:
        parsed_url = urllib.parse.urlparse(query)
        query = parsed_url.hostname or parsed_url.netloc.split(":")[0]
    query = query.rstrip("/")

    from helpers import _is_valid_ip
    is_ip = _is_valid_ip(query)
    lookup_target = query

    if not is_ip:
        try:
            lookup_target = socket.gethostbyname(query)
        except Exception:
            return jsonify({"error": "Could not resolve domain"}), 400

    geo_data = None
    try:
        geo_res = req.get(f"https://ipwho.is/{lookup_target}", timeout=5.0)
        geo_resp = geo_res.json()
        if geo_resp.get("success"):
            geo_data = {
                "ip": geo_resp.get("ip"),
                "country_code": geo_resp.get("country_code"),
                "country_name": geo_resp.get("country"),
                "city": geo_resp.get("city"),
                "region": geo_resp.get("region"),
                "timezone": geo_resp.get("timezone", {}).get("id"),
                "latitude": geo_resp.get("latitude"),
                "longitude": geo_resp.get("longitude"),
                "asn": geo_resp.get("connection", {}).get("asn"),
                "org": geo_resp.get("connection", {}).get("org"),
                "ip_type": geo_resp.get("type"),
                "currency_name": None,
                "currency": None,
                "languages": None
            }
    except Exception:
        pass

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

    whois_data = None
    try:
        w = whois_lib.whois(query)
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

    dns_records = {}
    for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME"):
        try:
            answers = dns.resolver.resolve(query, rtype, lifetime=3.0)
            dns_records[rtype.lower()] = [str(r) for r in answers][:8]
        except Exception:
            dns_records[rtype.lower()] = []

    if is_ip:
        try:
            hostname, _, _ = socket.gethostbyaddr(query)
            dns_records["ptr"] = hostname
        except Exception:
            dns_records["ptr"] = None
    else:
        dns_records["ptr"] = None

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

    radar_ranking = None
    if not is_ip:
        radar_ranking = get_cloudflare_radar_raw(query)

    return jsonify({
        "geo": geo_data,
        "vt": vt_stats,
        "whois": whois_data,
        "dns": dns_records,
        "ssl": ssl_info,
        "radar": radar_ranking,
    })
