import getpass
import hashlib
import secrets

# Simulated database storing: { username: {"salt": hex_string, "hash": hex_string} }
database = {}

def get_salt() -> str:
    """Generates a 16-byte cryptographically secure random salt."""
    return secrets.token_hex(16)

def compute_hash(password: str, salt: str) -> str:
    """Combines password and salt, then generates a SHA-256 digest."""
    salted_data = (salt + password).encode('utf-8')
    return hashlib.sha256(salted_data).hexdigest()

def register():
    """Prompts user input and registers a new user."""
    print("\n--- User Registration ---")
    username = input("Enter new username: ").strip()
    
    if not username:
        print("[-] Username cannot be empty.")
        return

    if username in database:
        print(f"[!] Error: Username '{username}' already exists.")
        return

    try:
        password = getpass.getpass("Enter new password: ")
    except Exception:
        password = input("Enter new password: ")

    if not password:
        print("[-] Password cannot be empty.")
        return

    salt = get_salt()
    pw_hash = compute_hash(password, salt)

    # Store only the salt and the digest (never plaintext)
    database[username] = {
        "salt": salt,
        "hash": pw_hash
    }
    print(f"[+] User '{username}' registered successfully!")

def login():
    """Prompts user input and verifies credentials."""
    print("\n--- User Login ---")
    username = input("Enter username: ").strip()
    
    try:
        password_attempt = getpass.getpass("Enter password: ")
    except Exception:
        password_attempt = input("Enter password: ")

    if username not in database:
        print("[-] Login Failed: Invalid username or password.")
        return

    # Fetch stored salt and valid hash
    stored_salt = database[username]["salt"]
    stored_hash = database[username]["hash"]

    # Hash incoming attempt with the stored salt
    attempt_hash = compute_hash(password_attempt, stored_salt)

    # Constant-time comparison to prevent timing attacks
    if secrets.compare_digest(attempt_hash, stored_hash):
        print(f"[+] Login Successful: Welcome, {username}!")
    else:
        print("[-] Login Failed: Invalid username or password.")

def view_database():
    """Displays stored database entries for lab verification."""
    print("\n--- Stored Database State ---")
    if not database:
        print("Database is currently empty.")
        return

    for user, info in database.items():
        print(f"User : {user}")
        print(f"Salt : {info['salt']}")
        print(f"Hash : {info['hash']}")
        print("-" * 40)

def main():
    while True:
        print("\n==============================")
        print(" SECURE LOGIN SYSTEM (HASH+SALT) ")
        print("==============================")
        print("1. Register User")
        print("2. Login")
        print("3. View Database State (Lab Demo)")
        print("4. Exit")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            view_database()
        elif choice == "4":
            print("Exiting program. Goodbye!")
            break
        else:
            print("[-] Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()
