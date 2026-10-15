import hashlib
import secrets
from datetime import datetime
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Simulated in-memory database storing:
# { username: {"salt": hex_string, "hash": hex_string, "created_at": iso_string} }
database = {}

def get_salt() -> str:
    """Generates a 16-byte cryptographically secure random salt."""
    return secrets.token_hex(16)

def compute_hash(password: str, salt: str) -> str:
    """Combines password and salt, then generates a SHA-256 digest."""
    salted_data = (salt + password).encode('utf-8')
    return hashlib.sha256(salted_data).hexdigest()

def seed_demo_data():
    """Seeds the in-memory database with demonstration users."""
    database.clear()
    
    # Alice with password 'Password123!'
    alice_salt = get_salt()
    alice_hash = compute_hash("Password123!", alice_salt)
    database["alice"] = {
        "salt": alice_salt,
        "hash": alice_hash,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # Bob with the EXACT SAME password 'Password123!' to visually prove
    # that different salts yield completely different hashes (Rainbow Table prevention).
    bob_salt = get_salt()
    bob_hash = compute_hash("Password123!", bob_salt)
    database["bob"] = {
        "salt": bob_salt,
        "hash": bob_hash,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

# Initialize demo seed
seed_demo_data()

@app.route("/")
def index():
    """Serves the primary web dashboard."""
    return render_template("index.html")

@app.route("/api/register", methods=["POST"])
def register_api():
    """Registers a new user with a cryptographically secure salt and SHA-256 hash."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if not username:
        return jsonify({
            "success": False,
            "error": "Username cannot be empty."
        }), 400

    if username in database:
        return jsonify({
            "success": False,
            "error": f"Username '{username}' already exists."
        }), 409

    if not password:
        return jsonify({
            "success": False,
            "error": "Password cannot be empty."
        }), 400

    salt = get_salt()
    pw_hash = compute_hash(password, salt)

    # Store only the salt and the digest (never plaintext password)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    database[username] = {
        "salt": salt,
        "hash": pw_hash,
        "created_at": created_at
    }

    return jsonify({
        "success": True,
        "message": f"User '{username}' registered successfully!",
        "user": {
            "username": username,
            "salt": salt,
            "hash": pw_hash,
            "salt_len_bytes": 16,
            "salt_hex_len": len(salt),
            "hash_algorithm": "SHA-256",
            "hash_hex_len": len(pw_hash),
            "created_at": created_at
        }
    }), 201

@app.route("/api/login", methods=["POST"])
def login_api():
    """Verifies credentials using constant-time comparison to prevent timing attacks."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password_attempt = str(data.get("password", ""))

    if not username or not password_attempt:
        return jsonify({
            "success": False,
            "message": "Username and password are required.",
            "diagnostics": None
        }), 400

    if username not in database:
        return jsonify({
            "success": False,
            "message": "Login Failed: Invalid username or password.",
            "diagnostics": {
                "user_found": False,
                "reason": "User does not exist in database"
            }
        }), 401

    # Fetch stored salt and valid hash
    stored_salt = database[username]["salt"]
    stored_hash = database[username]["hash"]

    # Hash incoming attempt with the stored salt
    attempt_hash = compute_hash(password_attempt, stored_salt)

    # Constant-time comparison to prevent timing attacks
    is_valid = secrets.compare_digest(attempt_hash, stored_hash)

    diagnostics = {
        "user_found": True,
        "username": username,
        "retrieved_salt": stored_salt,
        "attempt_hash": attempt_hash,
        "stored_hash": stored_hash,
        "digest_match": is_valid,
        "comparison_method": "secrets.compare_digest (constant-time)"
    }

    if is_valid:
        return jsonify({
            "success": True,
            "message": f"Login Successful: Welcome, {username}!",
            "diagnostics": diagnostics
        }), 200
    else:
        return jsonify({
            "success": False,
            "message": "Login Failed: Invalid username or password.",
            "diagnostics": diagnostics
        }), 401

@app.route("/api/database", methods=["GET"])
def get_database_state():
    """Returns the current stored database state."""
    users = [
        {
            "username": user,
            "salt": info["salt"],
            "hash": info["hash"],
            "created_at": info.get("created_at", "N/A")
        }
        for user, info in database.items()
    ]
    return jsonify({
        "success": True,
        "count": len(users),
        "database": users
    }), 200

@app.route("/api/reset", methods=["POST"])
def reset_database():
    """Resets database back to default demonstration seed."""
    seed_demo_data()
    return jsonify({
        "success": True,
        "message": "Database reset to initial demo state (Alice & Bob seeded)."
    }), 200

@app.route("/api/simulate-hash", methods=["POST"])
def simulate_hash():
    """Interactive sandbox endpoint for demonstrating salt + password hashing."""
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", ""))
    salt = str(data.get("salt", "")).strip()

    if not salt:
        salt = get_salt()

    salted_input = salt + password
    digest = hashlib.sha256(salted_input.encode('utf-8')).hexdigest()

    return jsonify({
        "success": True,
        "salt": salt,
        "password": password,
        "combined": salted_input,
        "utf8_bytes_len": len(salted_input.encode('utf-8')),
        "algorithm": "SHA-256",
        "digest": digest
    }), 200

# Precomputed Rainbow Table of common passwords for interactive demo
COMMON_PASSWORDS = [
    "password", "123456", "admin", "secret", "qwerty", "welcome",
    "Password123!", "login", "root", "toor", "pass123", "letmein",
    "master", "iloveyou", "dragon", "monkey", "sunshine", "football"
]
RAINBOW_TABLE = {
    hashlib.sha256(pwd.encode('utf-8')).hexdigest(): pwd
    for pwd in COMMON_PASSWORDS
}

@app.route("/api/compare-salt-demo", methods=["POST"])
def compare_salt_demo():
    """Generates comparison between unsalted vs salted hashes for 3 users."""
    data = request.get_json(silent=True) or {}
    password = str(data.get("password", "Password123!")) or "Password123!"

    unsalted_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    unsalted_users = [
        {"user": "User_1 (Alice)", "password": password, "hash": unsalted_hash},
        {"user": "User_2 (Bob)", "password": password, "hash": unsalted_hash},
        {"user": "User_3 (Carol)", "password": password, "hash": unsalted_hash},
    ]

    salted_users = []
    for uname in ["User_1 (Alice)", "User_2 (Bob)", "User_3 (Carol)"]:
        salt = get_salt()
        s_hash = compute_hash(password, salt)
        salted_users.append({
            "user": uname,
            "password": password,
            "salt": salt,
            "hash": s_hash
        })

    return jsonify({
        "success": True,
        "password": password,
        "unsalted_hash": unsalted_hash,
        "unsalted_users": unsalted_users,
        "salted_users": salted_users
    }), 200

@app.route("/api/rainbow-lookup", methods=["POST"])
def rainbow_lookup():
    """Simulates a Rainbow Table lookup on a candidate hash."""
    data = request.get_json(silent=True) or {}
    hash_query = str(data.get("hash", "")).strip().lower()

    if not hash_query:
        return jsonify({"success": False, "error": "Hash is required"}), 400

    if hash_query in RAINBOW_TABLE:
        return jsonify({
            "success": True,
            "found": True,
            "recovered_plaintext": RAINBOW_TABLE[hash_query],
            "message": "VULNERABILITY DEMO: Hash cracked instantly via Precomputed Rainbow Table!"
        }), 200
    else:
        return jsonify({
            "success": True,
            "found": False,
            "recovered_plaintext": None,
            "message": "DEFENSE DEMO: Hash NOT found in Rainbow Table. Salted hash protects user password!"
        }), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
