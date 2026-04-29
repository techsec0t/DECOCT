import json
import os
import re
import sys
import ipaddress
import sys
import subprocess
import shutil
import hashlib
import secrets
from datetime import datetime
from getpass import getpass
from hash_utils import calculate_hash
from remote_utils import remote_file_hash

EVIDENCE_DB = "evidence.json"
AUDIT_LOG = "audit.log"
ORG_FILE = "org_config.json"
ACCOUNTS_FILE = "accounts.sec"
MAX_USERS = 5
CURRENT_USER = None
CURRENT_IS_ADMIN = False
ADMIN_ONLY_OPTIONS = {"5", "6", "7", "8"}
ORIGINAL_USER = None
ORIGINAL_IS_ADMIN = None
TEMP_ADMIN = False

# ---------------- Colors ----------------
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# ---------------- Banner ----------------
def show_banner():
    banner = f"""
{CYAN}██████╗ ███████╗ ██████╗  ██████╗  ██████╗ ████████╗
██╔══██╗██╔════╝██╔════╝ ██╔═══██╗██╔════╝ ╚══██╔══╝
██║  ██║█████╗  ██║      ██║   ██║██║         ██║
██║  ██║██╔══╝  ██║      ██║   ██║██║         ██║
██████╔╝███████╗╚██████╗  ██████╔╝╚██████╗    ██║
╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝    ╚═╝{RESET}

{GREEN}       DECOCT – Digital Evidence Chain-of-Custody Tool{RESET}
{YELLOW}                       Blue Team Edition{RESET}

{BLUE}Version: 1.0{RESET}   {BLUE}Author: PYD{RESET}
"""
    print(banner)
#---------------------------------------------
def show_admin_warning():
    """Show professional warning depending on admin type"""
    global TEMP_ADMIN, CURRENT_IS_ADMIN

    print("\n" + "="*60)

    if TEMP_ADMIN:
        print("⚠️  TEMPORARY ADMIN ACCESS ⚠️")
        print(f"You are currently using ADMIN privileges as {CURRENT_USER}.")
        print("Use this access carefully. Any improper action may cause compliance issues or evidence corruption.")
        print("Audit logs are recording all your actions.\n")
    elif CURRENT_IS_ADMIN:
        print("⚠️  ADMIN ACCOUNT ⚠️")
        print(f"You are logged in as ADMIN: {CURRENT_USER}.")
        print("You have administrative privileges, but misuse may damage evidence or violate procedures.")
        print("Please operate responsibly.\n")

    print("="*60 + "\n")
# ---------------- Required Libraries ----------------
REQUIRED_LIBS = ["paramiko", "ipaddress"]  # add others as needed

def bootstrap_environment():
    # ---------------- Check Python Version ----------------
    if sys.version_info < (3, 6):
        print("\033[91m[!] Python 3.6+ is required.\033[0m")
        print("Download Python here: https://www.python.org/downloads/")
        sys.exit(1)
    
    print("\033[92m[+] Python version OK\033[0m")

    # ---------------- Check pip ----------------
    pip_path = shutil.which("pip3") or shutil.which("pip")
    if not pip_path:
        print("\033[93m[!] pip not found. Installing pip...\033[0m")
        try:
            subprocess.check_call([sys.executable, "-m", "ensurepip", "--upgrade"])
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
            print("\033[92m[+] pip installed successfully!\033[0m")
        except subprocess.CalledProcessError:
            print("\033[91m[!] Failed to install pip. Install manually and rerun tool.\033[0m")
            sys.exit(1)
    else:
        print("\033[92m[+] pip is available\033[0m")

    # ---------------- Check Required Libraries ----------------
    for lib in REQUIRED_LIBS:
        try:
            __import__(lib)
            print(f"\033[92m[+] Library '{lib}' found\033[0m")
        except ImportError:
            print(f"\033[93m[!] Library '{lib}' is missing.\033[0m")
            choice = input(f"Do you want to install '{lib}' now? [Y/N]: ").strip().lower()
            if choice == "y":
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
                    print(f"\033[92m[+] Library '{lib}' installed successfully!\033[0m")
                except subprocess.CalledProcessError:
                    print(f"\033[91m[!] Failed to install '{lib}'. Install manually and rerun tool.\033[0m")
                    sys.exit(1)
            else:
                print(f"\033[91m[!] '{lib}' is required. Exiting tool.\033[0m")
                sys.exit(1)

# ---------------- EXIT HANDLING ----------------

def handle_exit():
    choice = input("\n⚠️ Do you want to exit the tool? (y/n): ").strip().lower()
    if choice == "y":
        print("👋 Exiting tool safely.")
        sys.exit(0)
    print("↩️ Returning to tool...\n")

# ---------------- LOGGING ----------------

def log_action(action):
    with open(AUDIT_LOG, "a") as log:
        log.write(f"{datetime.now()} | {action}\n")

def load_evidence():
    if not os.path.exists(EVIDENCE_DB):
        return {}
    with open(EVIDENCE_DB, "r") as f:
        return json.load(f)

def load_accounts():
    if not os.path.exists(ACCOUNTS_FILE):
        return {}

    try:
        with open(ACCOUNTS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

def save_accounts(accounts):
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(accounts, f, indent=4)
    os.chmod(ACCOUNTS_FILE, 0o600)

def save_evidence(data):
    with open(EVIDENCE_DB, "w") as f:
        json.dump(data, f, indent=4)
        
#-------------------------------------------
import re

def validate_password_strength(password):
    """
    Password policy:
    - At least 8 characters
    - At least 1 lowercase
    - At least 1 uppercase
    - At least 1 digit
    - At least 1 symbol
    """
    if len(password) < 8:
        return False

    patterns = [
        r"[a-z]",      # lowercase
        r"[A-Z]",      # uppercase
        r"[0-9]",      # digit
        r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\[\]]"  # symbol
    ]

    return all(re.search(p, password) for p in patterns)


def prompt_strong_password(prompt="Password"):
    print("\n🔐 Password must contain:")
    print(" • Minimum 8 characters")
    print(" • At least 1 uppercase letter")
    print(" • At least 1 lowercase letter")
    print(" • At least 1 digit")
    print(" • At least 1 symbol\n")

    while True:
        pwd = getpass(f"{prompt}: ")
        if validate_password_strength(pwd):
            return pwd
        print("❌ Weak password. Please follow the policy.\n")

        
# ---------------- EVIDENCE ID MANAGEMENT ----------------

def get_next_evidence_id(evidence):
    if not evidence:
        return 1
    ids = [v.get("id", 0) for v in evidence.values()]
    return max(ids) + 1

# ---------------- REINDEX EVIDENCE IDS ----------------

def reindex_evidence_ids(evidence):
    """
    Reassign IDs sequentially starting from 1
    based on current sorted order.
    """
    sorted_items = sorted(evidence.items(), key=lambda x: x[1].get("id", 0))

    for new_id, (path, data) in enumerate(sorted_items, start=1):
        data["id"] = new_id

    return evidence

# ---------------- VALIDATION HELPERS ----------------

def is_valid_ip(ip):
    """
    Strict IPv4 validation:
    - Must be a valid IPv4
    - Must NOT be 0.0.0.0 or 255.255.255.255
    - Reject loopback (127.*.*.*) and link-local (169.254.*.*)
    """
    try:
        addr = ipaddress.IPv4Address(ip)
        if addr.is_unspecified:  # 0.0.0.0
            return False
        if ip == "255.255.255.255":  # broadcast
            return False
        if addr.is_loopback:  # 127.*.*.*
            return False
        if addr.is_link_local:  # 169.254.*.*
            return False
        return True
    except ipaddress.AddressValueError:
        return False
        
def safe_input(prompt_text):
    try:
        return input(prompt_text)
    except KeyboardInterrupt:
        handle_exit()
        return safe_input(prompt_text)

def safe_password(prompt_text):
    try:
        return getpass(prompt_text)
    except KeyboardInterrupt:
        handle_exit()
        return safe_password(prompt_text)

def prompt_non_empty(prompt_text):
    while True:
        value = safe_input(prompt_text).strip()
        if value:
            return value
        print("❌ This field cannot be empty.")

def prompt_ip():
    while True:
        ip = safe_input("Remote Host IP: ").strip()
        if is_valid_ip(ip):
            return ip
        print("❌ Invalid IP address. Please re-enter (example: 192.168.1.10).")

def prompt_existing_local_file():
    while True:
        path = safe_input("Enter local evidence file path: ").strip()
        if os.path.isfile(path):
            return path
        print("❌ File not found. Please re-enter correct path.")

def prompt_password():
    while True:
        pwd = safe_password("SSH Password: ")
        if pwd:
            return pwd
        print("❌ Password cannot be empty.")

def prompt_remote_hash(host, username, password, remote_path):
    file_hash = remote_file_hash(host, username, password, remote_path)
    if not file_hash:
        print("❌ Unable to access remote file. Check IP / username / path.")
    return file_hash
    
# ---------------- PATH EXPANSION HELPERS ----------------

def expand_local_paths(input_paths):
    """
    Accepts comma separated files or folders.
    Expands folders recursively into file paths.
    """
    final_paths = []
    paths_list = [p.strip() for p in input_paths.split(",") if p.strip()]

    for path in paths_list:
        if os.path.isfile(path):
            final_paths.append(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    final_paths.append(os.path.join(root, f))
        else:
            print(f"❌ Path not found: {path}")

    return final_paths


def expand_remote_paths(host, username, password, input_paths):
    """
    Accepts comma separated remote files or folders.
    Expands remote folders recursively into file paths via SSH.
    """
    import paramiko

    final_paths = []
    paths_list = [p.strip() for p in input_paths.split(",") if p.strip()]

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)

        for path in paths_list:
            # Check if file
            stdin, stdout, stderr = ssh.exec_command(f'test -f "{path}" && echo FILE')
            if stdout.read().decode().strip() == "FILE":
                final_paths.append(path)
                continue

            # Check if directory
            stdin, stdout, stderr = ssh.exec_command(f'test -d "{path}" && echo DIR')
            if stdout.read().decode().strip() == "DIR":
                # Recursively list files
                stdin, stdout, stderr = ssh.exec_command(f'find "{path}" -type f')
                files = stdout.read().decode().splitlines()
                final_paths.extend(files)
            else:
                print(f"❌ Remote path not found: {path}")

        ssh.close()

    except Exception as e:
        print(f"❌ SSH error while expanding paths: {e}")

    return final_paths
    
# ---------------- FIELD NAVIGATION ENGINE ----------------
MENU_SIGNAL = "__MENU__"

BACK_SIGNAL = "__BACK__"

def nav_input(prompt_text, hidden=False):
    """
    Supports:
    - 0 = go back to previous field
    - hidden input for passwords
    """
    try:
        if hidden:
            value = getpass(prompt_text + ": ")
        else:
            value = safe_input(prompt_text + ": ").strip()

        if value == "0":
            return BACK_SIGNAL

        return value

    except KeyboardInterrupt:
        handle_exit()

def run_field_form(fields):
    """
    Supports:
    0 in first field  -> return to main menu
    0 in other field  -> go to previous field
    """
    print("\n🔹 Type 0 anytime to go back\n")

    data = {}
    index = 0

    while index < len(fields):
        field = fields[index]

        value = nav_input(field["prompt"], hidden=field.get("hidden", False))

        # --- Handle BACK ---
        if value == BACK_SIGNAL:
            if index == 0:
                return MENU_SIGNAL
            index -= 1
            continue

        if not field["validator"](value):
            print("❌ Invalid input.")
            continue

        data[field["key"]] = value
        index += 1

    return data

def not_empty(val):
    return bool(val.strip())

def valid_ip(val):
    return is_valid_ip(val)
    
# ---------------- SECURITY HELPERS ----------------

def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, hashed

def verify_password(password, stored_salt, stored_hash):
    return hashlib.sha256((stored_salt + password).encode()).hexdigest() == stored_hash
    
def require_admin_reauth():
    print("\n🔐 Admin authorization required")

    password = getpass("Enter ADMIN password: ")

    accounts = load_accounts()

    for user, acc in accounts.items():
        if acc.get("is_admin"):
            if verify_password(password, acc["salt"], acc["hash"]):
                return True

    print("❌ Admin authentication failed.")
    return False

# ---------------- LOCAL ----------------

def register_evidence():
    """
    Register one or more local files at once (comma-separated)
    """
    fields = [
    {"key": "paths", "prompt": "Enter local evidence file path(s) (comma separated)", "validator": not_empty},
    {"key": "custodian", "prompt": "Custodian Name", "validator": not_empty},
    {"key": "purpose", "prompt": "Purpose of Collection", "validator": not_empty},
    ]

    form = run_field_form(fields)

    if form == MENU_SIGNAL:
        return

    paths = form["paths"]
    custodian = form["custodian"]
    purpose = form["purpose"]
    
    paths_list = expand_local_paths(paths)

    evidence = load_evidence()

    for file_path in paths_list:
        if not os.path.isfile(file_path):
            print(f"❌ File not found: {file_path}")
            continue
        file_hash = calculate_hash(file_path)
        eid = get_next_evidence_id(evidence)
        evidence[file_path] = {
            "id": eid,
            "type": "local",
            "hash": file_hash,
            "custodian": custodian,
            "purpose": purpose,
            "timestamp": str(datetime.now())
        }
        log_action(f"LOCAL REGISTERED | {file_path}")
        print(f"✅ Local evidence registered: {file_path}")

    evidence = reindex_evidence_ids(evidence)
    save_evidence(evidence)


# ---------------- VERIFY BY ID (LOCAL + REMOTE) ----------------

def verify_evidence():
    evidence = load_evidence()
    if not evidence:
        print("No evidence registered.")
        return

    show_evidence_table(evidence)

    ids_input = safe_input("Enter Evidence ID(s) to verify (comma separated): ").strip()
    ids = [int(x.strip()) for x in ids_input.split(",") if x.strip().isdigit()]

    if not ids:
        print("❌ No valid IDs entered.")
        return

    # Track remote sessions per host (avoid repeated SSH logins)
    ssh_sessions = {}

    for path, data in evidence.items():
        if data.get("id") not in ids:
            continue

        print(f"\n🔍 Verifying ID {data['id']} -> {path}")

        # -------- LOCAL --------
        if data["type"] == "local":
            if not os.path.exists(path):
                print("❌ File missing.")
                log_action(f"LOCAL MISSING | {path}")
                continue

            if calculate_hash(path) == data["hash"]:
                print("✅ Local evidence intact.")
                log_action(f"LOCAL VERIFIED | {path}")
            else:
                print("🚨 TAMPERING DETECTED")
                log_action(f"LOCAL ALERT | {path}")

        # -------- REMOTE --------
        elif data["type"] == "remote":
            host, remote_path = path.split(":", 1)

            # Open SSH session once per host
            if host not in ssh_sessions:
                fields = [
                    {"key": "username", "prompt": f"SSH Username for {host}", "validator": not_empty},
                    {"key": "password", "prompt": "SSH Password", "validator": not_empty, "hidden": True},
                ]

                form = run_field_form(fields)

                if form == MENU_SIGNAL:
                    return KeyboardInterrupt

                ssh_sessions[host] = (form["username"], form["password"])

            username, password = ssh_sessions[host]

            print(f"🌐 Checking remote file: {remote_path}")

            current_hash = prompt_remote_hash(host, username, password, remote_path)

            if not current_hash:
                print("❌ Unable to access remote file.")
                log_action(f"REMOTE ACCESS FAIL | {path}")
                continue

            if current_hash == data["hash"]:
                print("✅ Remote evidence intact.")
                log_action(f"REMOTE VERIFIED | {path}")
            else:
                print("🚨 REMOTE TAMPERING DETECTED")
                log_action(f"REMOTE ALERT | {path}")

# ---------------- REMOTE ----------------

def register_remote_evidence():
    """
    Register one or more remote files at once (comma-separated)
    """
    fields = [
    {"key": "host", "prompt": "Remote Host IP", "validator": valid_ip},
    {"key": "username", "prompt": "SSH Username", "validator": not_empty},
    {"key": "password", "prompt": "SSH Password", "validator": not_empty, "hidden": True},
    {"key": "remote_paths", "prompt": "Enter remote file path(s) (comma separated)", "validator": not_empty},
    {"key": "custodian", "prompt": "Custodian Name", "validator": not_empty},
    {"key": "purpose", "prompt": "Purpose", "validator": not_empty},
    ]

    form = run_field_form(fields)

    if form == MENU_SIGNAL:
        return

    host = form["host"]
    username = form["username"]
    password = form["password"]
    remote_paths = form["remote_paths"]
    custodian = form["custodian"]
    purpose = form["purpose"]
    
    paths_list = expand_remote_paths(host, username, password, remote_paths)

    evidence = load_evidence()

    for remote_path in paths_list:
        print(f"🔍 Calculating hash for {remote_path}...")
        file_hash = prompt_remote_hash(host, username, password, remote_path)
        if not file_hash:
            continue

        key = f"{host}:{remote_path}"
        eid = get_next_evidence_id(evidence)
        evidence[key] = {
            "id": eid,
            "type": "remote",
            "hash": file_hash,
            "custodian": custodian,
            "purpose": purpose,
            "timestamp": str(datetime.now())
        }
        log_action(f"REMOTE REGISTERED | {key}")
        print(f"✅ Remote evidence registered: {key}")

    evidence = reindex_evidence_ids(evidence)
    save_evidence(evidence)

# ---------------- TABLE VIEW ----------------

def show_evidence_table(evidence):
    if not evidence:
        print("No evidence records found.")
        return

    print("\n" + "-" * 95)
    print(f"{'ID':<5} {'TYPE':<8} {'CUSTODIAN':<15} {'TIMESTAMP':<22} PATH")
    print("-" * 95)

    sorted_items = sorted(evidence.items(), key=lambda x: x[1].get("id", 0))

    for path, data in sorted_items:
        print(f"{data.get('id', ''):<5} {data['type']:<8} {data['custodian']:<15} {data['timestamp']:<22} {path}")

    print("-" * 95)
    
# ---------------- DELETE EVIDENCE ----------------

def delete_evidence():
    if not require_admin_reauth():
        return

    evidence = load_evidence()
    if not evidence:
        print("No evidence to delete.")
        return

    show_evidence_table(evidence)

    ids_input = safe_input("Enter Evidence ID(s) to delete (comma separated): ").strip()
    ids = [int(x.strip()) for x in ids_input.split(",") if x.strip().isdigit()]

    to_delete = []

    for path, data in evidence.items():
        if data.get("id") in ids:
            to_delete.append(path)

    if not to_delete:
        print("❌ No matching evidence IDs found.")
        return

    for path in to_delete:
        print(f"🗑️ Deleting: {path}")
        log_action(f"EVIDENCE DELETED | {path}")
        del evidence[path]

    # Reindex after deletion
    evidence = reindex_evidence_ids(evidence)
    save_evidence(evidence)

    print("✅ Selected evidence deleted and IDs reordered.")

# ---------------- VIEW & RESET ----------------

def view_custody():
    evidence = load_evidence()
    show_evidence_table(evidence)

def reset_tool():
    if not require_admin_reauth():
        return

    confirm = safe_input("⚠️ Type YES to reset tool: ").strip()
    if confirm == "YES":
        if os.path.exists(EVIDENCE_DB):
            os.remove(EVIDENCE_DB)
        if os.path.exists(AUDIT_LOG):
            os.remove(AUDIT_LOG)
        print("✅ Tool reset complete.")
    else:
        print("❌ Reset cancelled.")
        
def setup_organization():
    print("\n=== First Time Organization Setup ===")

    # --- Organization name ---
    while True:
        org_name = safe_input("Organization Name: ").strip()
        if org_name:
            break
        print("❌ Organization name cannot be empty.")

    print("\n🔐 Create PRIMARY ADMIN account (cannot be deleted)")

    # --- Admin username ---
    while True:
        admin_user = safe_input("Admin username: ").strip()
        if admin_user:
            break
        print("❌ Username cannot be empty.")

    # --- Admin full name ---
    while True:
        admin_name = safe_input("Admin full name: ").strip()
        if admin_name:
            break
        print("❌ Full name cannot be empty.")

    admin_role = "Administrator"

    # --- Admin password ---
    while True:
        admin_pass = prompt_strong_password("Admin password")
        if admin_pass:
            break
        print("❌ Password cannot be empty.")

    # --- Hash password ---
    salt, hashed = hash_password(admin_pass)

    # --- Create accounts structure ---
    accounts = {
        admin_user: {
            "fullname": admin_name,
            "role": admin_role,
            "salt": salt,
            "hash": hashed,
            "is_admin": True
        }
    }

    # --- Save organization file ---
    with open(ORG_FILE, "w") as f:
        json.dump({"org_name": org_name}, f, indent=4)

    # --- Save accounts file securely ---
    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(accounts, f, indent=4)

    os.chmod(ACCOUNTS_FILE, 0o600)

    print("\n✅ Organization setup complete.")
    print("🔒 Primary admin account created successfully.\n")

def login():
    global CURRENT_USER, CURRENT_IS_ADMIN, TEMP_ADMIN, ORIGINAL_USER, ORIGINAL_IS_ADMIN

    if not os.path.exists(ORG_FILE) or os.path.getsize(ORG_FILE) == 0:
        setup_organization()

    with open(ORG_FILE) as f:
        org = json.load(f)

    print(f"\n🔐 Welcome to {org['org_name']} Evidence System")

    while True:
        print("\n1. Login with existing account")
        print("2. Create new account")
        print("3. Exit")

        choice = safe_input("Select option: ").strip()

        if choice == "3":
            print("👋 Exiting tool.")
            sys.exit(0)

        if choice == "2":
            add_account()
            continue

        if choice != "1":
            continue

        try:
            with open(ACCOUNTS_FILE) as f:
                accounts = json.load(f)
        except:
            setup_organization()
            continue

        username = safe_input("Username: ").strip()
        password = getpass("Password: ")

        if username in accounts:
            acc = accounts[username]
            if verify_password(password, acc["salt"], acc["hash"]):
                CURRENT_USER = username
                CURRENT_IS_ADMIN = acc.get("is_admin", False)
                print(f"✅ Login successful. Role: {acc['role']}") 
                if CURRENT_IS_ADMIN or TEMP_ADMIN:
                    show_admin_warning()
                return
           


        print("❌ Wrong credentials")
        forgot = safe_input("Forgot password? (y/n): ").lower()
        if forgot == "y":
            reset_password(accounts)

def add_account():
    accounts = load_accounts()

    if len(accounts) >= 5:
        print("❌ Maximum 5 accounts allowed.")
        return

    fields = [
        {"key": "username", "prompt": "New Username", "validator": not_empty},
        {"key": "fullname", "prompt": "Full Name", "validator": not_empty},
        {"key": "role", "prompt": "Role", "validator": not_empty},
    ]

    form = run_field_form(fields)
    if form is None:
        return

    username = form["username"]

    if username in accounts:
        print("❌ Username already exists.")
        return
    password = prompt_strong_password("Password")
    salt, hashed = hash_password(password)


    accounts[username] = {
        "fullname": form["fullname"],
        "role": form["role"],
        "salt": salt,
        "hash": hashed,
        "is_admin": False
    }

    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(accounts, f, indent=4)

    print(f"✅ Account '{username}' created successfully.")
    
def reset_password(accounts):
    username = safe_input("Enter username: ").strip()
    role = safe_input("Enter your role: ").strip()

    if username not in accounts:
        print("❌ User not found.")
        return

    if accounts[username]["role"] != role:
        print("❌ Role mismatch.")
        return

    new_pass = prompt_strong_password("Enter new password")
    salt, hashed = hash_password(new_pass)

    accounts[username]["salt"] = salt
    accounts[username]["hash"] = hashed

    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(accounts, f)

    print("✅ Password reset successful.")
    log_action(f"PASSWORD RESET | {username}")

def delete_account():
    global CURRENT_USER

    with open(ACCOUNTS_FILE) as f:
        accounts = json.load(f)

    # List deletable accounts
    deletable = [
        u for u, a in accounts.items()
        if not a["is_admin"] and u != CURRENT_USER
    ]

    if not deletable:
        print("❌ No accounts available to delete.")
        return

    print("\nAccounts you can delete:")
    for i, u in enumerate(deletable, 1):
        print(f"{i}. {u} ({accounts[u]['role']})")

    choice = safe_input("Select account to delete (0 to go back): ").strip()

# --- Go back ---
    if choice == "0":
        print("↩️ Returning to menu.")
        return

# --- Validate choice ---
    if not choice.isdigit():
        print("❌ Invalid selection.")
        return

    choice = int(choice)

    if choice < 1 or choice > len(deletable):
        print("❌ Invalid selection.")
        return

    target_user = deletable[choice - 1]

    # Admin password required
    print("\n🔐 Admin authentication required to delete account")
    admin_pass = getpass("Enter ADMIN password: ")

    # find admin account
    admin_acc = next(a for a in accounts.values() if a["is_admin"])

    if not verify_password(admin_pass, admin_acc["salt"], admin_acc["hash"]):
        print("❌ Wrong admin password.")
        return

    del accounts[target_user]

    with open(ACCOUNTS_FILE, "w") as f:
        json.dump(accounts, f)

    print(f"✅ Account '{target_user}' deleted.")
    log_action(f"ACCOUNT DELETED | {target_user} by {CURRENT_USER}")

def view_accounts():
    # --- Admin-only check ---
    if not CURRENT_IS_ADMIN:
        print("❌ Access denied. Admin privileges required.")
        return

    accounts = load_accounts()
    if not accounts:
        print("No accounts found.")
        return

    print("\n" + "-" * 60)
    print(f"{'USERNAME':<15} {'FULL NAME':<20} {'ROLE':<15} ADMIN")
    print("-" * 60)

    for username, acc in accounts.items():
        admin_flag = "YES" if acc.get("is_admin") else "NO"
        print(
            f"{username:<15} "
            f"{acc.get('fullname', ''):<20} "
            f"{acc.get('role', ''):<15} "
            f"{admin_flag}"
        )

    print("-" * 60)
    

def return_to_original_account():
    global CURRENT_IS_ADMIN, TEMP_ADMIN

    if not TEMP_ADMIN:
        print("❌ You are not using temporary admin privileges.")
        return

    CURRENT_IS_ADMIN = ORIGINAL_IS_ADMIN
    TEMP_ADMIN = False

    log_action(
        f"TEMP ADMIN REVOKED | user={CURRENT_USER}"
    )

    print("↩️ Returned to original account privileges.")


# ---------------- TEMP ADMIN ----------------
TEMP_ADMIN = False
ORIGINAL_USER = None
ORIGINAL_IS_ADMIN = False

def elevate_to_admin():
    """Temporarily give normal user admin privileges"""
    global TEMP_ADMIN, ORIGINAL_USER, ORIGINAL_IS_ADMIN, CURRENT_USER, CURRENT_IS_ADMIN

    if CURRENT_IS_ADMIN:
        print("ℹ️ You already have admin privileges.")
        show_admin_warning()
        return

    print("\n🔐 Requesting temporary admin privileges...")
    password = getpass("Enter ADMIN password: ")

    accounts = load_accounts()
    # Find any admin account
    admin_acc = next((a for a in accounts.values() if a.get("is_admin")), None)

    if admin_acc and verify_password(password, admin_acc["salt"], admin_acc["hash"]):
        # Save original account info
        ORIGINAL_USER = CURRENT_USER
        ORIGINAL_IS_ADMIN = CURRENT_IS_ADMIN

        # Elevate to admin
        CURRENT_USER = f"{CURRENT_USER} (TEMP_ADMIN)"
        CURRENT_IS_ADMIN = True
        TEMP_ADMIN = True

        log_action(f"TEMP ADMIN ACCESS GRANTED | by {ORIGINAL_USER}")

        print("✅ Temporary admin privileges granted.\n")
        show_admin_warning()
    else:
        print("❌ Admin authentication failed. Cannot elevate privileges.")
        log_action(f"TEMP ADMIN ACCESS FAILED | attempted by {CURRENT_USER}")

def return_to_original_account():
    """Return to original normal account"""
    global TEMP_ADMIN, CURRENT_USER, CURRENT_IS_ADMIN

    CURRENT_USER = ORIGINAL_USER
    CURRENT_IS_ADMIN = ORIGINAL_IS_ADMIN
    TEMP_ADMIN = False
    log_action(f"TEMP ADMIN ACCESS RETURNED | {CURRENT_USER}")
    print("↩️ Returned to original account privileges.\n")

# ---------------- MAIN ----------------
def main():
    #show_banner()
    #bootstrap_environment()
    global CURRENT_USER, CURRENT_IS_ADMIN, TEMP_ADMIN, ORIGINAL_USER, ORIGINAL_IS_ADMIN
    while True:
        print("\n=== Digital Evidence Chain-of-Custody ===")
        if CURRENT_IS_ADMIN or TEMP_ADMIN:
            # Full admin menu
            print("1. Register Local Evidence")
            print("2. Register Remote Evidence")
            print("3. Verify Local Evidence")
            print("4. View Chain-of-Custody Records")
            print("5. Delete Evidence")
            print("6. Reset Tool")
            print("7. Add User Account")
            print("8. Delete User Account")
            print("9. View User Accounts")
            print("10. Exit")
            print("0. Logout / Go back")
            if TEMP_ADMIN:
                print("11. Return to your normal account")
        else:  # Normal user menu (renumbered sequentially)
            print("1. Register Local Evidence")
            print("2. Register Remote Evidence")
            print("3. Verify Local Evidence")
            print("4. View Chain-of-Custody Records")
            print("5. Request Temporary Admin Access")
            print("6. Exit")
            print("0. Logout / Go back")

        choice = safe_input("Select option: ").strip()
        
        if choice == "0":
            print("🔹 Returning to login menu...")
            # Reset flags
            CURRENT_USER = None
            CURRENT_IS_ADMIN = False
            TEMP_ADMIN = False
            ORIGINAL_USER = None
            ORIGINAL_IS_ADMIN = False
            break  # exit menu loop, go back to outer loop → login again


        # ---------------- Admin / Temp Admin Options ----------------
        if choice == "1":
            register_evidence()
        elif choice == "2":
            register_remote_evidence()
        elif choice == "3":
            verify_evidence()
        elif choice == "4":
            view_custody()
        elif choice == "5" and (CURRENT_IS_ADMIN or TEMP_ADMIN):
            delete_evidence()
        elif choice == "6" and (CURRENT_IS_ADMIN or TEMP_ADMIN):
            reset_tool()
        elif choice == "7" and (CURRENT_IS_ADMIN or TEMP_ADMIN):
            add_account()
        elif choice == "8" and (CURRENT_IS_ADMIN or TEMP_ADMIN):
            delete_account()
        elif choice == "9" and (CURRENT_IS_ADMIN or TEMP_ADMIN):
            view_accounts()
        elif (choice == "10" and (CURRENT_IS_ADMIN or TEMP_ADMIN)) or (choice == "6" and not CURRENT_IS_ADMIN):
            print("Goodbye 👋")
            exit()

        # ---------------- TEMP ADMIN FEATURES ----------------
        elif choice == "5" and not CURRENT_IS_ADMIN:
            elevate_to_admin()
        elif choice == "11" and TEMP_ADMIN:
            return_to_original_account()

        else:
            print("❌ Invalid option.")


if __name__ == "__main__":
    os.system("clear" if os.name != "nt" else "cls")
    show_banner()
    bootstrap_environment()  
    while True:
        login()
        main()
