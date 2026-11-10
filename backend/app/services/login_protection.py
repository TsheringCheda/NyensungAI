
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import Lock


# =========================================
# LOGIN PROTECTION CONFIGURATION
# =========================================

ACCOUNT_FAILURE_LIMIT = 5
ACCOUNT_WINDOW_SECONDS = 300

IP_FAILURE_LIMIT = 10
IP_WINDOW_SECONDS = 60

LOCKOUT_SECONDS = 900


# =========================================
# IN-MEMORY LOGIN TRACKING
# =========================================

account_attempts = defaultdict(deque)
ip_attempts = defaultdict(deque)

account_blocks = {}
ip_blocks = {}

protection_lock = Lock()


# =========================================
# CURRENT UTC TIME
# =========================================

def current_time():
    return datetime.now(timezone.utc)


# =========================================
# REMOVE EXPIRED ATTEMPTS
# =========================================

def clean_attempts(attempts, window_seconds, now):

    cutoff = now - timedelta(seconds=window_seconds)

    while attempts and attempts[0] <= cutoff:
        attempts.popleft()


# =========================================
# CHECK WHETHER LOGIN IS RESTRICTED
# =========================================

def check_login_restriction(source_ip, email):

    now = current_time()

    account_key = (source_ip, email)

    with protection_lock:

        account_block = account_blocks.get(account_key)
        ip_block = ip_blocks.get(source_ip)

        if account_block and now < account_block:
            return {
                "blocked": True,
                "reason": "Too many failed login attempts for this account and IP.",
                "retry_after": max(
                    1, int((account_block - now).total_seconds())
                )
            }

        if ip_block and now < ip_block:
            return {
                "blocked": True,
                "reason": "Too many failed login attempts from this IP.",
                "retry_after": max(
                    1, int((ip_block - now).total_seconds())
                )
            }

        # Remove expired restrictions
        if account_block and now >= account_block:
            account_blocks.pop(account_key, None)

        if ip_block and now >= ip_block:
            ip_blocks.pop(source_ip, None)

        return {
            "blocked": False,
            "reason": None,
            "retry_after": 0
        }


# =========================================
# RECORD FAILED LOGIN
# =========================================

def record_failed_login(source_ip, email):

    now = current_time()

    account_key = (source_ip, email)

    with protection_lock:

        account_queue = account_attempts[account_key]
        ip_queue = ip_attempts[source_ip]

        clean_attempts(
            account_queue,
            ACCOUNT_WINDOW_SECONDS,
            now
        )

        clean_attempts(
            ip_queue,
            IP_WINDOW_SECONDS,
            now
        )

        account_queue.append(now)
        ip_queue.append(now)

        account_blocked = (
            len(account_queue) >= ACCOUNT_FAILURE_LIMIT
        )

        ip_blocked = (
            len(ip_queue) >= IP_FAILURE_LIMIT
        )

        if account_blocked:
            account_blocks[account_key] = (
                now + timedelta(seconds=LOCKOUT_SECONDS)
            )

        if ip_blocked:
            ip_blocks[source_ip] = (
                now + timedelta(seconds=LOCKOUT_SECONDS)
            )

        return {
            "account_blocked": account_blocked,
            "ip_blocked": ip_blocked,
            "account_failures": len(account_queue),
            "ip_failures": len(ip_queue)
        }
