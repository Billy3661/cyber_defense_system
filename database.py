import sqlite3
import os

DATABASE_URL = os.environ.get("DATABASE_URL")

def using_postgres():
    return DATABASE_URL is not None

def get_db_connection():
    if using_postgres():
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "cyber_defense.db"))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def _p(query):
    if using_postgres():
        q = query.replace("?", "%s")
        q = q.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        return q
    return query

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(_p("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            profile_image TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    try:
        cur.execute(_p("ALTER TABLE users ADD COLUMN profile_image TEXT DEFAULT ''"))
    except Exception:
        pass

    cur.execute(_p("""
        CREATE TABLE IF NOT EXISTS user_settings (
            username TEXT PRIMARY KEY,
            vt_api_key TEXT DEFAULT '',
            wigle_api_key TEXT DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """))
    try:
        cur.execute(_p("ALTER TABLE user_settings ADD COLUMN wigle_api_key TEXT DEFAULT ''"))
    except Exception:
        pass

    cur.execute(_p("""
        CREATE TABLE IF NOT EXISTS malware_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_value TEXT UNIQUE NOT NULL,
            threat_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """))

    cur.execute(_p("SELECT COUNT(*) FROM malware_signatures"))
    if cur.fetchone()[0] == 0:
        default_sigs = [
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR Test Signature", "High", "Standard antivirus verification test file."),
            ("24d00b42f2d6fbcd7952f9714a6d2f3b828731671b56fb8e49c7161bf27cc11b", "WannaCry Ransomware", "Critical", "Encrypting ransomware strain targeting SMB vulnerabilities."),
            ("ed97d37b84b094c0b1bbd6bc3a2b5358965e3e37cf7d5c7c00a886a11df3c030", "WannaCry Ransomware Variant", "Critical", "Secondary WannaCry variant spreading globally."),
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0e", "Emotet Downloader", "Critical", "Modular banking trojan used as an access broker."),
            ("41b83f06e32d1e2e1e550e599e09d1663fc695ec2fe2a2c4538aabf651fd0f", "Cobalt Strike Beacon", "High", "Adversary simulation software payload used in cyber espionage.")
        ]
        cur.executemany(_p("""
            INSERT INTO malware_signatures (hash_value, threat_name, severity, details)
            VALUES (?, ?, ?, ?)
        """), default_sigs)

    conn.commit()
    conn.close()

def create_user(username, password_hash):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            _p("INSERT INTO users (username, password_hash) VALUES (?, ?)"),
            (username, password_hash)
        )
        conn.commit()
        success = True
    except Exception:
        conn.rollback()
        success = False
    finally:
        conn.close()
    return success

def get_user_by_username(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(_p("SELECT * FROM users WHERE username = ?"), (username,))
    if using_postgres():
        cols = [desc[0] for desc in cur.description]
        row = cur.fetchone()
        result = dict(zip(cols, row)) if row else None
    else:
        row = cur.fetchone()
        result = dict(row) if row else None
    conn.close()
    return result

def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(_p(query), params)
    result = None
    if fetch_one:
        if using_postgres():
            cols = [desc[0] for desc in cur.description]
            row = cur.fetchone()
            result = dict(zip(cols, row)) if row else None
        else:
            row = cur.fetchone()
            result = dict(row) if row else None
    elif fetch_all:
        if using_postgres():
            cols = [desc[0] for desc in cur.description]
            rows = cur.fetchall()
            result = [dict(zip(cols, row)) for row in rows] if rows else []
        else:
            rows = cur.fetchall()
            result = [dict(row) for row in rows] if rows else []
    else:
        conn.commit()
    conn.close()
    return result

def get_user_vt_key(username):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(_p("SELECT vt_api_key FROM user_settings WHERE username = ?"), (username,))
    if using_postgres():
        row = cur.fetchone()
        result = row[0] if row else ""
    else:
        row = cur.fetchone()
        result = row["vt_api_key"] if row else ""
    conn.close()
    return result

def set_user_vt_key(username, key):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(_p("""
        INSERT INTO user_settings (username, vt_api_key, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(username) DO UPDATE SET
            vt_api_key = excluded.vt_api_key,
            updated_at = CURRENT_TIMESTAMP
    """), (username, key))
    conn.commit()
    conn.close()

def get_malware_by_hash(hash_value):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(_p("SELECT * FROM malware_signatures WHERE hash_value = ?"), (hash_value.lower(),))
    if using_postgres():
        cols = [desc[0] for desc in cur.description]
        row = cur.fetchone()
        result = dict(zip(cols, row)) if row else None
    else:
        row = cur.fetchone()
        result = dict(row) if row else None
    conn.close()
    return result

def add_malware_signature(hash_value, threat_name, severity, details):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(_p("""
            INSERT INTO malware_signatures (hash_value, threat_name, severity, details)
            VALUES (?, ?, ?, ?)
        """), (hash_value.lower(), threat_name, severity, details))
        conn.commit()
        success = True
    except Exception:
        conn.rollback()
        success = False
    finally:
        conn.close()
    return success