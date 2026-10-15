# Secure Login System (Salt + SHA-256) Web & CLI Application

An interactive cryptographic web dashboard and authentication system built with Python (Flask) demonstrating salted password hashing and timing-safe authentication.

---

## Key Features

1. **Cryptographically Secure Salt Generation**:
   - Uses `secrets.token_hex(16)` from Python's standard library to generate high-entropy 16-byte random salts.
2. **SHA-256 Digest**:
   - Combines `salt + password` before computing `hashlib.sha256()`.
   - Never stores plaintext passwords in memory or database.
3. **Rainbow Table Mitigation**:
   - Demonstrates that identical passwords generate completely unique hashes due to random salting.
4. **Timing-Attack Safe Verification**:
   - Compares candidate hash with stored hash using `secrets.compare_digest()` to prevent side-channel timing attacks.
5. **Interactive Web Dashboard**:
   - **User Registration**: Real-time visualization of salt generation and hash creation.
   - **User Login**: Step-by-step telemetry of the authentication and verification pipeline.
   - **Database State Inspector**: Live view of stored users, salts, and digests with 1-click clipboard copy and search filter.
   - **Cryptography Sandbox & Explainer**: Test arbitrary text and salts to see SHA-256 digests in real time.

---

## Quick Start

### 1. Run the Web Application
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

### 2. Run the Original CLI Version
```bash
python cli_app.py
```

### 3. Run Automated Tests
```bash
python -m pytest tests/ -v
```

---

## Project Structure

```
crypto/
├── app.py                 # Flask web backend & REST API
├── cli_app.py             # Original CLI interactive script
├── requirements.txt       # Dependencies (Flask, pytest)
├── README.md              # Project documentation
├── templates/
│   └── index.html         # Web dashboard UI
├── static/
│   ├── css/
│   │   └── style.css      # Dark cybersecurity aesthetic styles
│   └── js/
│       └── app.js         # Reactive UI & REST API client
└── tests/
    └── test_app.py        # Automated test suite (11 tests)
```
