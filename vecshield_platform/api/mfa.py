"""Second-factor primitives for local accounts (ADR 0004).

A thin layer over two maintained libraries so VecShield carries no OTP or QR
code of its own:

* `pyotp <https://github.com/pyauth/pyotp>`_ generates and checks RFC 6238
  time-based one-time passwords (SHA-1, 6 digits, 30-second steps — what every
  authenticator app expects) and builds the ``otpauth://`` provisioning URI.
* `segno <https://github.com/heuer/segno>`_ renders that URI as a QR code, as
  an SVG ``data:`` URI the console can show without a JavaScript QR library.

pyotp is stateless, so the one thing added here is replay protection:
:func:`verify_totp` returns the time step a code matched, the caller stores
it, and a later call refuses that step and every earlier one. A code can
therefore be used once, even inside its validity window.

Recovery codes are random (80 bits) and stored only as SHA-256, the same way
session tokens are; their entropy makes a slow KDF unnecessary.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone
from typing import Optional

import pyotp
import segno

ISSUER = "VecShield"
#: Steps either side of "now" that are accepted, for clock drift.
VALID_WINDOW = 1
RECOVERY_CODE_COUNT = 10
#: 20 hex characters = 80 bits, shown as four groups of five.
_RECOVERY_HEX_CHARS = 20

_DIGITS_RE = re.compile(r"^\d{6}$")
_HEX_RE = re.compile(r"^[0-9a-f]{%d}$" % _RECOVERY_HEX_CHARS)


def new_secret() -> str:
    """A new base32 TOTP secret (160 bits from :mod:`secrets`)."""
    return pyotp.random_base32()


def provisioning(secret: str, username: str) -> dict:
    """What an authenticator app needs: the ``otpauth://`` URI and its QR code."""
    uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER)
    return {
        "secret": secret,
        "uri": uri,
        "qr_svg": segno.make(uri, error="m").svg_data_uri(
            scale=4, border=2, dark="#000000", light="#ffffff"),
    }


def normalize_totp(code: object) -> Optional[str]:
    """``"123 456"`` -> ``"123456"``; ``None`` if it is not a six-digit code."""
    text = re.sub(r"[\s-]", "", str(code or ""))
    return text if _DIGITS_RE.fullmatch(text) else None


def verify_totp(secret: str, code: object, *, now: float,
                last_step: Optional[int] = None) -> Optional[int]:
    """Return the time step ``code`` matches, or ``None``.

    Steps within :data:`VALID_WINDOW` of ``now`` are tried; any step at or
    before ``last_step`` (the last one accepted for this secret) is refused,
    so a code that has been used once is not accepted again.
    """
    otp = normalize_totp(code)
    if otp is None or not secret:
        return None
    totp = pyotp.TOTP(secret)
    current = totp.timecode(datetime.fromtimestamp(now, tz=timezone.utc))
    matched: Optional[int] = None
    # Compare against every candidate (no early exit) so timing does not
    # reveal which step matched.
    for step in range(current - VALID_WINDOW, current + VALID_WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if pyotp.utils.strings_equal(otp, totp.generate_otp(step)) and matched is None:
            matched = step
    return matched


def new_recovery_codes(n: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Fresh single-use recovery codes, formatted ``xxxxx-xxxxx-xxxxx-xxxxx``."""
    codes = []
    for _ in range(n):
        raw = secrets.token_hex(_RECOVERY_HEX_CHARS // 2)
        codes.append("-".join(raw[i:i + 5] for i in range(0, len(raw), 5)))
    return codes


def normalize_recovery_code(code: object) -> Optional[str]:
    """Strip separators and case; ``None`` if it cannot be a recovery code."""
    text = re.sub(r"[\s-]", "", str(code or "")).lower()
    return text if _HEX_RE.fullmatch(text) else None


def hash_recovery_code(code: str) -> str:
    """SHA-256 of a recovery code in normalized form; raises on a malformed one."""
    normalized = normalize_recovery_code(code)
    if normalized is None:
        raise ValueError("not a recovery code")
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()
