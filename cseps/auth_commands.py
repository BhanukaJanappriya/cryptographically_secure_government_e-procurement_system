"""
CSePS Authentication Commands
==============================
Handles user registration, login, logout, whoami.
"""

import sys
from config import (
    ROLE_AUTHORITY, ROLE_BIDDER, ROLE_EVALUATOR, ALL_ROLES, MIN_PASSWORD_LEN,
    C_GREEN, C_YELLOW, C_CYAN, C_BOLD, C_RESET, C_DIM
)
from crypto_engine import KeyManager
from storage import UserStore, SessionStore, LedgerStore
from display import (
    print_main_banner, print_section_banner, print_result_banner,
    print_success, print_error, print_warning, print_info,
    print_key_value_block, print_crypto, print_ledger, print_step,
    role_badge, blank, divider, prompt, prompt_password,
    prompt_choice, prompt_confirm, working, short_hash,
)


def cmd_register(args: list[str]):
    """Register a new user account with ECC key pair generation."""
    print_section_banner("New User Registration", "👤")
    blank()

    # Collect user details
    print(f"  {C_DIM}Select account role:{C_RESET}")
    role = prompt_choice("Role", ALL_ROLES)
    blank()

    username = prompt("Username (alphanumeric, no spaces)")
    if not username.replace("-", "").replace("_", "").isalnum():
        print_error("Username must be alphanumeric (hyphens/underscores allowed).")
        sys.exit(1)

    if UserStore.user_exists(username):
        print_error(f"Username '{username}' is already registered.")
        sys.exit(1)

    full_name    = prompt("Full name")
    organisation = prompt("Organisation / Company name")

    blank()
    print(f"  {C_DIM}Set a password (min {MIN_PASSWORD_LEN} characters):{C_RESET}")
    while True:
        password = prompt_password("Password")
        if len(password) < MIN_PASSWORD_LEN:
            print_error(f"Password too short (min {MIN_PASSWORD_LEN} chars).")
            continue
        confirm = prompt_password("Confirm password")
        if password != confirm:
            print_error("Passwords do not match.")
            continue
        break

    # Generate ECC key pair
    blank()
    working("Generating ECC P-384 key pair")
    priv, pub = KeyManager.generate_keypair()
    priv_pem  = KeyManager.private_key_to_pem(priv)
    pub_pem   = KeyManager.public_key_to_pem(pub)
    fp        = KeyManager.fingerprint(pub_pem)
    print_crypto(f"ECC SECP384R1 key pair generated. Fingerprint: {fp}")

    # Persist
    working("Registering account")
    UserStore.register(
        username=username, password=password, role=role,
        full_name=full_name, organisation=organisation,
        public_key_pem=pub_pem,
    )
    UserStore.save_private_key(username, priv_pem)

    # Ledger entry
    working("Recording registration on audit ledger")
    entry = LedgerStore.append(
        event_type="USER_REGISTERED",
        actor=username,
        proc_id="SYSTEM",
        payload={
            "username":     username,
            "role":         role,
            "organisation": organisation,
            "key_fingerprint": fp,
        }
    )
    print_ledger(f"Ledger entry #{entry['seq']} | Chain: {short_hash(entry['chain_hash'])}")

    print_result_banner(f"Registration successful! Welcome, {full_name}", ok=True)
    print_key_value_block([
        ("Username",        username),
        ("Role",            role.upper()),
        ("Organisation",    organisation),
        ("Key Fingerprint", fp),
        ("Ledger Entry",    f"#{entry['seq']}"),
    ])
    blank()
    print(f"  {C_DIM}You can now log in with: python main.py login{C_RESET}")
    blank()


def cmd_login(args: list[str]):
    """Authenticate and create a session."""
    print_section_banner("Login", "🔑")
    blank()

    username = prompt("Username")
    password = prompt_password("Password")

    working("Authenticating")
    user = UserStore.authenticate(username, password)
    if not user:
        print_result_banner("Authentication failed. Invalid username or password.", ok=False)
        sys.exit(1)

    SessionStore.login(username, user["role"])

    LedgerStore.append(
        event_type="USER_LOGIN",
        actor=username,
        proc_id="SYSTEM",
        payload={"username": username, "role": user["role"]},
    )

    print_result_banner(f"Login successful. Welcome back, {user['full_name']}!", ok=True)
    print_key_value_block([
        ("Logged in as",  f"{user['full_name']}"),
        ("Role",          role_badge(user["role"])),
        ("Organisation",  user["organisation"]),
    ])
    blank()


def cmd_logout(args: list[str]):
    """End the current session."""
    session = SessionStore.current()
    if not session:
        print_warning("No active session.")
        return

    LedgerStore.append(
        event_type="USER_LOGOUT",
        actor=session["username"],
        proc_id="SYSTEM",
        payload={"username": session["username"]},
    )
    SessionStore.logout()
    print_success(f"Logged out. Session ended for '{session['username']}'.")
    blank()


def cmd_whoami(args: list[str]):
    """Display current session info."""
    session = SessionStore.current()
    if not session:
        print_warning("No active session. Use: python main.py login")
        return

    user = UserStore.get_user(session["username"])
    print_section_banner("Current Session", "👤")
    blank()
    print_key_value_block([
        ("Username",        user["username"]),
        ("Full Name",       user["full_name"]),
        ("Role",            role_badge(user["role"])),
        ("Organisation",    user["organisation"]),
        ("Registered At",   user["registered_at"][:19].replace("T", " ") + " UTC"),
        ("Key Fingerprint", KeyManager.fingerprint(user["public_key_pem"])),
    ])
    blank()
