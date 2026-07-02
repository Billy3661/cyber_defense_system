import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "cyber_defense.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            profile_image TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Try to add column if table already exists
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN profile_image TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_settings (
            username TEXT PRIMARY KEY,
            vt_api_key TEXT DEFAULT '',
            wigle_api_key TEXT DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Try to add column if table already exists
    try:
        cursor.execute("ALTER TABLE user_settings ADD COLUMN wigle_api_key TEXT DEFAULT ''")
    except sqlite3.OperationalError:
        pass
        
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS malware_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash_value TEXT UNIQUE NOT NULL,
            threat_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT NOT NULL
        )
    """)
    # Seed default signatures if table is empty
    cursor.execute("SELECT COUNT(*) FROM malware_signatures")
    if cursor.fetchone()[0] == 0:
        default_sigs = [
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR Test Signature", "High", "Standard antivirus verification test file."),
            ("24d00b42f2d6fbcd7952f9714a6d2f3b828731671b56fb8e49c7161bf27cc11b", "WannaCry Ransomware", "Critical", "Encrypting ransomware strain targeting SMB vulnerabilities."),
            ("ed97d37b84b094c0b1bbd6bc3a2b5358965e3e37cf7d5c7c00a886a11df3c030", "WannaCry Ransomware Variant", "Critical", "Secondary WannaCry variant spreading globally."),
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0e", "Emotet Downloader", "Critical", "Modular banking trojan used as an access broker."),
            ("41b83f06e32d1e2e1e550e599e09d1663fc695ec2fe2a2c4538aabf651fd0f", "Cobalt Strike Beacon", "High", "Adversary simulation software payload used in cyber espionage.")
        ]
        cursor.executemany("""
            INSERT INTO malware_signatures (hash_value, threat_name, severity, details)
            VALUES (?, ?, ?, ?)
        """, default_sigs)
        
    conn.commit()
    conn.close()

def create_user(username, password_hash):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        conn.close()
    return success

def get_user_by_username(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def execute_query(query, params=(), fetch_one=False, fetch_all=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(query, params)
    
    result = None
    if fetch_one:
        result = cursor.fetchone()
    elif fetch_all:
        result = cursor.fetchall()
    else:
        conn.commit()
        
    conn.close()
    return result

def get_user_vt_key(username):
    """Return the stored VirusTotal API key for the user (or empty string)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT vt_api_key FROM user_settings WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return row["vt_api_key"] if row else ""

def set_user_vt_key(username, key):
    """Upsert the VirusTotal API key for the user."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO user_settings (username, vt_api_key, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(username) DO UPDATE SET
            vt_api_key = excluded.vt_api_key,
            updated_at = CURRENT_TIMESTAMP
    """, (username, key))
    conn.commit()
    conn.close()

def get_malware_by_hash(hash_value):
    """Check if a file hash matches a known malware signature in the local database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM malware_signatures WHERE hash_value = ?", (hash_value.lower(),))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def add_malware_signature(hash_value, threat_name, severity, details):
    """Add a new malware signature to the local offline database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO malware_signatures (hash_value, threat_name, severity, details)
            VALUES (?, ?, ?, ?)
        """, (hash_value.lower(), threat_name, severity, details))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        conn.close()
    return success


