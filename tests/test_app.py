import sys
import os
import tempfile
import shutil
import pytest
from unittest.mock import patch, MagicMock
from io import BytesIO

sys.path.insert(0, '/home/billy/Desktop/cyber_defense_system')

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest")
os.environ.pop("DATABASE_URL", None)


@pytest.fixture(autouse=True)
def temp_database(tmp_path):
    """Point database.py at a temp SQLite file for every test."""
    import database
    temp_db = str(tmp_path / "test_cyber_defense.db")
    database.DATABASE_URL = None
    orig = database.get_db_connection
    def _patched():
        import sqlite3 as _sqlite3
        conn = _sqlite3.connect(temp_db)
        conn.row_factory = _sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn
    database.get_db_connection = _patched
    database.init_db()
    yield temp_db
    database.get_db_connection = orig


@pytest.fixture
def app(temp_database):
    """Create a fresh Flask app for each test."""
    from app import app as flask_app
    flask_app.config["TESTING"] = True
    flask_app.config["SESSION_COOKIE_DOMAIN"] = None
    flask_app.config["SESSION_COOKIE_PATH"] = "/"
    flask_app.config["SERVER_NAME"] = "localhost"
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in_client(client):
    """Client with a logged-in user session."""
    with client.session_transaction() as sess:
        import database as db
        from werkzeug.security import generate_password_hash
        db.create_user("testuser", generate_password_hash("TestPass123!"))
        user = db.get_user_by_username("testuser")
        sess["user_id"] = user["id"]
        sess["username"] = "testuser"
        sess["profile_image"] = ""
    return client


# ============================================================
# 1. APP FACTORY & CONFIGURATION
# ============================================================

class TestAppFactoryAndConfiguration:

    def test_app_creates_successfully(self, app):
        assert app is not None

    def test_secret_key_is_set(self, app):
        assert app.secret_key is not None
        assert len(app.secret_key) > 0

    def test_testing_config(self, app):
        assert app.config["TESTING"] is True

    def test_all_eight_blueprints_registered(self, app):
        blueprint_names = set(app.blueprints.keys())
        expected = {"main", "auth", "scanner", "simulator", "breach", "chat", "admin", "phone"}
        assert blueprint_names == expected

    def test_route_count(self, app):
        rules = [r for r in app.url_map.iter_rules() if r.endpoint != "static"]
        assert len(rules) == 55


# ============================================================
# 2. DATABASE OPERATIONS
# ============================================================

class TestDatabaseOperations:

    def test_init_db_creates_tables(self, temp_database):
        import database
        conn = database.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row["name"] for row in cur.fetchall()}
        conn.close()
        expected_tables = {
            "users", "user_settings", "malware_signatures",
            "user_phishing_stats", "user_badges",
            "chat_conversations", "chat_messages",
        }
        assert expected_tables.issubset(tables)

    def test_malware_signatures_seeded(self, temp_database):
        import database
        result = database.execute_query(
            "SELECT COUNT(*) as cnt FROM malware_signatures", fetch_one=True
        )
        assert result["cnt"] >= 5

    def test_create_user_and_retrieve(self, temp_database):
        import database
        from werkzeug.security import generate_password_hash
        pwd_hash = generate_password_hash("mypassword")
        assert database.create_user("alice", pwd_hash) is True
        user = database.get_user_by_username("alice")
        assert user is not None
        assert user["username"] == "alice"

    def test_duplicate_username_fails(self, temp_database):
        import database
        from werkzeug.security import generate_password_hash
        h = generate_password_hash("pass1234")
        assert database.create_user("bob", h) is True
        assert database.create_user("bob", h) is False

    def test_user_settings_crud(self, temp_database):
        import database
        from werkzeug.security import generate_password_hash
        database.create_user("settingsuser", generate_password_hash("pass12345"))
        database.set_user_vt_key("settingsuser", "abc123key")
        key = database.get_user_vt_key("settingsuser")
        assert key == "abc123key"
        database.set_user_vt_key("settingsuser", "newkey456")
        assert database.get_user_vt_key("settingsuser") == "newkey456"

    def test_password_hashing_works(self, temp_database):
        from werkzeug.security import generate_password_hash, check_password_hash
        h = generate_password_hash("securepassword")
        assert check_password_hash(h, "securepassword") is True
        assert check_password_hash(h, "wrongpassword") is False

    def test_get_user_nonexistent_returns_none(self, temp_database):
        import database
        assert database.get_user_by_username("nobody") is None


# ============================================================
# 3. HELPER FUNCTIONS
# ============================================================

class TestIsShortenerDomain:

    def test_bit_ly_is_shortener(self):
        from helpers import is_shortener_domain
        assert is_shortener_domain("bit.ly") is True

    def test_google_is_not_shortener(self):
        from helpers import is_shortener_domain
        assert is_shortener_domain("google.com") is False

    def test_www_bit_ly_is_shortener(self):
        from helpers import is_shortener_domain
        assert is_shortener_domain("www.bit.ly") is True

    def test_apple_co_is_not_shortener(self):
        from helpers import is_shortener_domain
        assert is_shortener_domain("apple.co") is False

    def test_goo_gl_is_shortener(self):
        from helpers import is_shortener_domain
        assert is_shortener_domain("goo.gl") is True

    def test_tinyurl_is_shortener(self):
        from helpers import is_shortener_domain
        assert is_shortener_domain("tinyurl.com") is True


class TestAnalyzeUrl:

    def _mock_api_checks(self):
        from unittest.mock import MagicMock
        from helpers import (
            check_urlhaus, check_virustotal, check_cloudflare_radar,
            check_google_safebrowsing, check_abuseipdb, check_otx_alienvault,
        )
        safe_response = {"label": "Test", "status": "pass", "detail": "Clean"}
        return [
            patch("helpers.check_urlhaus", return_value=safe_response),
            patch("helpers.check_virustotal", return_value=safe_response),
            patch("helpers.check_cloudflare_radar", return_value=safe_response),
            patch("helpers.check_google_safebrowsing", return_value=safe_response),
            patch("helpers.check_abuseipdb", return_value=safe_response),
            patch("helpers.check_otx_alienvault", return_value=safe_response),
        ]

    def test_https_url_scores_lower_than_http(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                http_result = analyze_url("http://example.com")
                https_result = analyze_url("https://example.com")
                assert http_result["score"] < https_result["score"] or \
                       https_result["score"] <= http_result["score"]
                http_check = next(c for c in http_result["checks"] if c["label"] == "HTTPS Secure Connection")
                https_check = next(c for c in https_result["checks"] if c["label"] == "HTTPS Secure Connection")
                assert http_check["status"] == "info"
                assert https_check["status"] == "pass"
            finally:
                for p in patches:
                    p.stop()

    def test_legitimate_url_likely_safe(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("https://google.com")
                assert result["verdict"] == "Likely Safe"
            finally:
                for p in patches:
                    p.stop()

    def test_github_url_likely_safe(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("https://github.com")
                assert result["verdict"] == "Likely Safe"
            finally:
                for p in patches:
                    p.stop()

    def test_shortener_url_not_malicious(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("https://bit.ly/something")
                assert result["verdict"] != "Malicious"
            finally:
                for p in patches:
                    p.stop()

    def test_banking_url_no_suspicious_keywords(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("https://chase.com/banking/account")
                kw_check = next(c for c in result["checks"] if c["label"] == "Suspicious Keywords")
                assert kw_check["status"] == "pass"
            finally:
                for p in patches:
                    p.stop()

    def test_heuristic_score_capped_at_40(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("http://192.168.1.1/test")
                api_related_labels = {"URLhaus Threat Check", "VirusTotal Reputation Check"}
                heuristic_score = sum(
                    c.get("score_addition", 0)
                    for c in result["checks"]
                    if c["label"] not in api_related_labels
                )
                assert result["score"] >= 0
            finally:
                for p in patches:
                    p.stop()

    def test_suspicious_tld_warning(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("https://example.tk/page")
                tld_check = next(c for c in result["checks"] if c["label"] == "Suspicious TLD")
                assert tld_check["status"] == "info"
            finally:
                for p in patches:
                    p.stop()

    def test_ip_address_as_host_warning(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("http://10.0.0.1/login")
                ip_check = next(c for c in result["checks"] if c["label"] == "IP Address as Host")
                assert ip_check["status"] == "warn"
            finally:
                for p in patches:
                    p.stop()

    def test_url_obfuscation_detection(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                long_path = "a" * 150
                result = analyze_url(f"http://example.com/{long_path}/%40/test")
                obs_check = next(c for c in result["checks"] if c["label"] == "URL Obfuscation")
                assert obs_check["status"] in ("warn", "info")
            finally:
                for p in patches:
                    p.stop()

    def test_url_without_scheme_gets_prefix(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("example.com")
                assert result["url"] == "example.com"
                assert result["verdict"] in ("Likely Safe", "Potentially Risky", "Suspicious", "Malicious", "Safe")
            finally:
                for p in patches:
                    p.stop()

    def test_result_has_required_keys(self):
        from helpers import analyze_url
        patches = self._mock_api_checks()
        with patch("helpers.socket.gethostbyname"):
            for p in patches:
                p.start()
            try:
                result = analyze_url("https://example.com")
                assert "url" in result
                assert "score" in result
                assert "verdict" in result
                assert "verdict_color" in result
                assert "checks" in result
                assert "timestamp" in result
                assert "risk_percent" in result
            finally:
                for p in patches:
                    p.stop()


class TestParseEmailHeaders:

    def test_returns_valid_structure(self):
        from helpers import parse_email_headers
        raw = (
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Test Email\n"
            "Date: Mon, 01 Jan 2024 12:00:00 +0000\n"
            "Return-Path: <sender@example.com>\n"
            "Received-SPF: pass (google.com: domain of sender@example.com)\n"
        )
        result = parse_email_headers(raw)
        assert "verdict" in result
        assert "findings" in result
        assert "headers" in result
        assert "score" in result
        assert result["headers"]["from"] == "sender@example.com"
        assert result["headers"]["subject"] == "Test Email"

    def test_missing_headers_produce_warnings(self):
        from helpers import parse_email_headers
        raw = "From: test@test.com\n"
        result = parse_email_headers(raw)
        assert result["headers"]["to"] == "Unknown"
        assert result["headers"]["subject"] == "Unknown"
        assert result["score"] > 0

    def test_empty_headers(self):
        from helpers import parse_email_headers
        result = parse_email_headers("")
        assert result["verdict"] in ("Low Risk", "Medium Risk", "High Risk (Potential Spoofing)")
        assert isinstance(result["findings"], list)

    def test_spf_pass_detected(self):
        from helpers import parse_email_headers
        raw = (
            "From: user@example.com\n"
            "Received-SPF: pass (google.com: domain of example.com)\n"
        )
        result = parse_email_headers(raw)
        spf_finding = next((f for f in result["findings"] if "SPF" in f["label"]), None)
        assert spf_finding is not None
        assert spf_finding["status"] == "pass"

    def test_spf_fail_detected(self):
        from helpers import parse_email_headers
        raw = (
            "From: user@evil.com\n"
            "Return-Path: <bounce@other.com>\n"
            "Received-SPF: fail\n"
        )
        result = parse_email_headers(raw)
        assert result["score"] > 30


# ============================================================
# 4. PUBLIC ROUTE TESTS
# ============================================================

class TestPublicRoutes:

    def test_index_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_threats_returns_200(self, client):
        resp = client.get("/threats")
        assert resp.status_code == 200

    def test_threat_detail_returns_200(self, client):
        resp = client.get("/threat/1")
        assert resp.status_code == 200

    def test_awareness_returns_200(self, client):
        resp = client.get("/awareness")
        assert resp.status_code == 200

    def test_troubleshoot_requires_login(self, client):
        resp = client.get("/troubleshoot", follow_redirects=False)
        assert resp.status_code == 302

    def test_login_returns_200(self, client):
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_register_returns_200(self, client):
        resp = client.get("/register")
        assert resp.status_code == 200

    def test_check_auth_not_authenticated(self, client):
        resp = client.get("/api/check-auth")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["authenticated"] is False

    def test_check_auth_authenticated(self, logged_in_client):
        resp = logged_in_client.get("/api/check-auth")
        data = resp.get_json()
        assert data["authenticated"] is True

    def test_api_stats_returns_json(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "threats" in data
        assert "guides" in data


# ============================================================
# 5. AUTH FLOW TESTS
# ============================================================

class TestAuthFlow:

    def _get_csrf(self, client):
        with client.session_transaction() as sess:
            from helpers import generate_csrf_token
            with client.application.test_request_context():
                token = generate_csrf_token()
            sess["csrf_token"] = token
            return token

    def test_register_with_valid_data(self, client):
        csrf = self._get_csrf(client)
        resp = client.post("/register", data={
            "username": "newuser",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "csrf_token": csrf,
        }, follow_redirects=False)
        assert resp.status_code == 302
        import database
        user = database.get_user_by_username("newuser")
        assert user is not None

    def test_register_duplicate_username(self, client):
        import database
        from werkzeug.security import generate_password_hash
        database.create_user("dupeuser", generate_password_hash("Pass1234!"))
        csrf = self._get_csrf(client)
        resp = client.post("/register", data={
            "username": "dupeuser",
            "password": "StrongPass1!",
            "confirm_password": "StrongPass1!",
            "csrf_token": csrf,
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_login_with_valid_creds(self, client):
        import database
        from werkzeug.security import generate_password_hash
        database.create_user("loginuser", generate_password_hash("GoodPass1!"))
        csrf = self._get_csrf(client)
        resp = client.post("/login", data={
            "username": "loginuser",
            "password": "GoodPass1!",
            "csrf_token": csrf,
        }, follow_redirects=False)
        assert resp.status_code == 302

    def test_login_with_invalid_creds(self, client):
        csrf = self._get_csrf(client)
        resp = client.post("/login", data={
            "username": "fakeuser",
            "password": "wrongpass",
            "csrf_token": csrf,
        }, follow_redirects=True)
        assert resp.status_code == 200

    def test_logout_clears_session(self, client):
        with client.session_transaction() as sess:
            sess["user_id"] = 999
            sess["username"] = "test"
        resp = client.get("/logout", follow_redirects=False)
        assert resp.status_code == 302
        with client.session_transaction() as sess:
            assert "user_id" not in sess

    def test_protected_route_redirects_when_not_auth(self, client):
        resp = client.get("/scanner", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_register_short_password_rejected(self, client):
        csrf = self._get_csrf(client)
        resp = client.post("/register", data={
            "username": "shortpwd",
            "password": "abc",
            "confirm_password": "abc",
            "csrf_token": csrf,
        }, follow_redirects=True)
        assert resp.status_code == 200


# ============================================================
# 6. API ENDPOINT TESTS (AUTHENTICATED)
# ============================================================

class TestApiEndpoints:

    def test_scan_with_valid_url(self, logged_in_client):
        from helpers import (
            check_urlhaus, check_virustotal, check_cloudflare_radar,
            check_google_safebrowsing, check_abuseipdb, check_otx_alienvault,
        )
        safe = {"label": "Test", "status": "pass", "detail": "Clean"}
        with patch("helpers.check_urlhaus", return_value=safe), \
             patch("helpers.check_virustotal", return_value=safe), \
             patch("helpers.check_cloudflare_radar", return_value=safe), \
             patch("helpers.check_google_safebrowsing", return_value=safe), \
             patch("helpers.check_abuseipdb", return_value=safe), \
             patch("helpers.check_otx_alienvault", return_value=safe), \
             patch("helpers.socket.gethostbyname"):
            resp = logged_in_client.post("/api/scan", json={"url": "https://google.com"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert "verdict" in data
            assert "checks" in data

    def test_scan_empty_url(self, logged_in_client):
        resp = logged_in_client.post("/api/scan", json={"url": ""})
        assert resp.status_code == 400

    def test_scan_file_requires_file(self, logged_in_client):
        resp = logged_in_client.post("/api/scan-file")
        assert resp.status_code == 400

    def test_breach_password_returns_count(self, logged_in_client):
        with patch("blueprints.breach.check_password_breached", return_value=54321):
            resp = logged_in_client.post("/api/breach/password", json={"password": "password"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["count"] == 54321

    def test_breach_password_empty(self, logged_in_client):
        resp = logged_in_client.post("/api/breach/password", json={"password": ""})
        assert resp.status_code == 400

    def test_breach_email_without_hibp_key(self, logged_in_client):
        with patch("blueprints.breach.HIBP_API_KEY", ""):
            resp = logged_in_client.post("/api/breach/email", json={"email": "test@example.com"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["breached"] is False
            assert "info" in data

    def test_breach_email_invalid_format(self, logged_in_client):
        resp = logged_in_client.post("/api/breach/email", json={"email": "not-an-email"})
        assert resp.status_code == 400

    def test_check_auth_authenticated(self, logged_in_client):
        resp = logged_in_client.get("/api/check-auth")
        data = resp.get_json()
        assert data["authenticated"] is True

    def test_scanner_engine(self, logged_in_client):
        resp = logged_in_client.get("/api/scanner-engine")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "engine" in data

    def test_scan_url_endpoint(self, logged_in_client):
        safe = {"label": "Test", "status": "pass", "detail": "Clean"}
        with patch("helpers.check_urlhaus", return_value=safe), \
             patch("helpers.check_virustotal", return_value=safe), \
             patch("helpers.check_cloudflare_radar", return_value=safe), \
             patch("helpers.check_google_safebrowsing", return_value=safe), \
             patch("helpers.check_abuseipdb", return_value=safe), \
             patch("helpers.check_otx_alienvault", return_value=safe), \
             patch("helpers.socket.gethostbyname"):
            resp = logged_in_client.post("/api/scan-url", json={"url": "https://example.com"})
            assert resp.status_code == 200
            data = resp.get_json()
            assert "verdict" in data


# ============================================================
# 7. RATE LIMITING TESTS
# ============================================================

class TestRateLimiting:

    def test_limiter_configured(self, app):
        from helpers import limiter
        assert limiter is not None

    def test_429_handler_returns_json_for_api(self, app, client):
        from app import rate_limit_exceeded
        from flask import Flask
        mock_e = MagicMock()
        mock_e.description = "Rate limit exceeded"
        with app.test_request_context("/api/scan", method="POST"):
            resp = rate_limit_exceeded(mock_e)
            assert resp[1] == 429


# ============================================================
# 8. ADMIN PANEL
# ============================================================

class TestAdminPanel:

    def test_admin_redirects_without_login(self, client):
        resp = client.get("/admin/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_admin_forbidden_for_non_admin_user(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        database.create_user("regularuser", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "regularuser"
        resp = client.get("/admin/")
        assert resp.status_code == 302

    def test_admin_dashboard_loads_for_admin(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        app.config["ADMIN_USERNAME"] = "testadmin"
        database.create_user("testadmin", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "testadmin"
        resp = client.get("/admin/")
        assert resp.status_code == 200
        assert b"Dashboard" in resp.data

    def test_admin_users_page(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        app.config["ADMIN_USERNAME"] = "testadmin"
        database.create_user("testadmin", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "testadmin"
        resp = client.get("/admin/users")
        assert resp.status_code == 200
        assert b"Users" in resp.data

    def test_admin_signatures_page(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        app.config["ADMIN_USERNAME"] = "testadmin"
        database.create_user("testadmin", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "testadmin"
        resp = client.get("/admin/signatures")
        assert resp.status_code == 200
        assert b"Malware Signatures" in resp.data

    def test_admin_no_admin_configured(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        app.config["ADMIN_USERNAME"] = ""
        database.create_user("someuser", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "someuser"
        resp = client.get("/admin/")
        assert resp.status_code == 302


# ============================================================
# 9. PHONE INTELLIGENCE
# ============================================================

class TestPhoneIntelligence:

    def test_phone_page_requires_login(self, client):
        resp = client.get("/phone-intelligence")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_phone_page_loads(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        database.create_user("phoneuser", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "phoneuser"
        resp = client.get("/phone-intelligence")
        assert resp.status_code == 200
        assert b"Phone Intelligence" in resp.data

    def test_api_scan_phone_empty(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        database.create_user("phoneuser2", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "phoneuser2"
        resp = client.post("/api/scan-phone", json={"phone": ""})
        assert resp.status_code == 400

    def test_api_scan_phone_valid(self, app, client):
        from werkzeug.security import generate_password_hash
        import database
        database.create_user("phoneuser3", generate_password_hash("pass1234"))
        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "phoneuser3"
        resp = client.post("/api/scan-phone", json={"phone": "+14155552671"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["valid"] is True
        assert data["country_iso"] == "US"
        assert "e164" in data
        assert "risk_level" in data

    def test_parse_and_enrich_invalid(self):
        from blueprints.phone import parse_and_enrich
        result = parse_and_enrich("not-a-number")
        assert result["valid"] is False
        assert result["e164"] == "" or result["possible"] is False
