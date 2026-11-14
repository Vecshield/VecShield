"""Two-step sign-in for local accounts (ADR 0004)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
from datetime import datetime, timezone

import pytest

pyotp = pytest.importorskip("pyotp")
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from vecshield_platform.api import create_app, mfa  # noqa: E402
from vecshield_platform.api.auth import AuthError, JWTAuthenticator  # noqa: E402
from vecshield_platform.api.config_store import ConfigStore  # noqa: E402
from vecshield_platform.api.users import (  # noqa: E402
    AccountLockedError,
    InvalidCredentialsError,
    InvalidSecondFactorError,
    MfaRequiredError,
    MfaStateError,
    UserStore,
)
from vecshield_platform.compliance import AuditLog  # noqa: E402

CSRF = {"X-VecShield-CSRF": "1"}
ADMIN_PW = "correct horse battery"
ALICE_PW = "alice-initial-pw-1"
ALICE_NEW_PW = "alice-chosen-pw-22"
T0 = 1_700_000_000.0


class Clock:
    def __init__(self, t: float = T0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("VECSHIELD_INITIAL_ADMIN_PASSWORD", "VECSHIELD_SESSION_IDLE_MINUTES",
                 "VECSHIELD_SESSION_MAX_HOURS", "VECSHIELD_LOGIN_MAX_ATTEMPTS",
                 "VECSHIELD_LOGIN_LOCKOUT_MINUTES", "VECSHIELD_MFA_REQUIRED",
                 "VECSHIELD_JWT_REQUIRE_MFA", "VECSHIELD_JWT_SECRET",
                 "VECSHIELD_SEPARATION_OF_DUTIES"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return UserStore(clock=clock)


@pytest.fixture
def audit():
    return AuditLog()


def _code(secret: str, clock: Clock) -> str:
    return pyotp.TOTP(secret).at(int(clock.t))


def _alice(store: UserStore) -> None:
    store.create_user("alice", ALICE_PW, ["viewer"], created_by="test")
    store.change_password("alice", ALICE_PW, ALICE_NEW_PW)


def _enroll(store: UserStore, clock: Clock, name="alice", pw=ALICE_NEW_PW):
    secret = store.begin_mfa_enrollment(name, pw)["secret"]
    codes = store.confirm_mfa_enrollment(name, _code(secret, clock))
    clock.advance(30)  # the confirmation code's step is spent
    return secret, codes


# ---- wrapper over pyotp --------------------------------------------------- #

def test_verify_accepts_one_step_either_side_only():
    secret = mfa.new_secret()
    totp = pyotp.TOTP(secret)
    for offset in (-30, 0, 30):
        assert mfa.verify_totp(secret, totp.at(int(T0 + offset)), now=T0) is not None
    for offset in (-60, 60):
        assert mfa.verify_totp(secret, totp.at(int(T0 + offset)), now=T0) is None


def test_verify_refuses_a_step_already_used():
    secret = mfa.new_secret()
    code = pyotp.TOTP(secret).at(int(T0))
    step = mfa.verify_totp(secret, code, now=T0)
    assert step == pyotp.TOTP(secret).timecode(datetime.fromtimestamp(T0, tz=timezone.utc))
    assert mfa.verify_totp(secret, code, now=T0, last_step=step) is None
    # An older code is refused too, even inside the drift window.
    earlier = pyotp.TOTP(secret).at(int(T0 - 30))
    assert mfa.verify_totp(secret, earlier, now=T0, last_step=step) is None


@pytest.mark.parametrize("bad", ["", None, "abcdef", "12345", "1234567", "12 34 5x"])
def test_verify_rejects_malformed_codes(bad):
    assert mfa.verify_totp(mfa.new_secret(), bad, now=T0) is None


def test_verify_tolerates_spaces():
    secret = mfa.new_secret()
    code = pyotp.TOTP(secret).at(int(T0))
    assert mfa.verify_totp(secret, f"{code[:3]} {code[3:]}", now=T0) is not None


def test_recovery_codes_are_random_and_hash_in_normal_form():
    codes = mfa.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    code = codes[0]
    assert len(code.replace("-", "")) == 20
    assert mfa.hash_recovery_code(code) == mfa.hash_recovery_code(
        code.replace("-", "").upper())
    with pytest.raises(ValueError):
        mfa.hash_recovery_code("123456")


def test_provisioning_uri_and_qr_code():
    secret = mfa.new_secret()
    data = mfa.provisioning(secret, "alice")
    assert data["uri"].startswith("otpauth://totp/VecShield:alice?")
    assert f"secret={secret}" in data["uri"]
    assert data["qr_svg"].startswith("data:image/svg+xml")


# ---- store ---------------------------------------------------------------- #

def test_password_without_code_asks_for_it_and_costs_nothing(clock):
    store = UserStore(clock=clock, max_attempts=3)
    _alice(store)
    _enroll(store, clock)
    for _ in range(5):
        with pytest.raises(MfaRequiredError):
            store.sign_in("alice", ALICE_NEW_PW)
    assert not store.is_locked("alice")


def test_code_signs_in_once(store, clock):
    _alice(store)
    secret, _ = _enroll(store, clock)
    code = _code(secret, clock)
    user, method = store.sign_in("alice", ALICE_NEW_PW, code)
    assert (user.username, user.mfa_enabled, method) == ("alice", True, "totp")
    with pytest.raises(InvalidSecondFactorError):
        store.sign_in("alice", ALICE_NEW_PW, code)


def test_wrong_codes_count_toward_lockout(clock):
    store = UserStore(clock=clock, max_attempts=3)
    _alice(store)
    secret, _ = _enroll(store, clock)
    for _ in range(3):
        with pytest.raises(InvalidSecondFactorError):
            store.sign_in("alice", ALICE_NEW_PW, "000000")
    assert store.is_locked("alice")
    with pytest.raises(AccountLockedError):
        store.sign_in("alice", ALICE_NEW_PW, _code(secret, clock))


def test_wrong_password_is_refused_before_the_code(store, clock):
    _alice(store)
    secret, _ = _enroll(store, clock)
    with pytest.raises(InvalidCredentialsError) as info:
        store.sign_in("alice", "not-the-password", _code(secret, clock))
    assert not isinstance(info.value, InvalidSecondFactorError)


def test_recovery_code_works_once(store, clock):
    _alice(store)
    _, codes = _enroll(store, clock)
    assert store.recovery_codes_remaining("alice") == 10
    _, method = store.sign_in("alice", ALICE_NEW_PW, codes[0].upper())
    assert method == "recovery_code"
    assert store.recovery_codes_remaining("alice") == 9
    with pytest.raises(InvalidSecondFactorError):
        store.sign_in("alice", ALICE_NEW_PW, codes[0])


def test_recovery_codes_are_stored_hashed(store, clock):
    _alice(store)
    _, codes = _enroll(store, clock)
    rows = store._conn.execute("SELECT code_sha256 FROM recovery_codes").fetchall()
    stored = {r["code_sha256"] for r in rows}
    assert stored == {hashlib.sha256(c.replace("-", "").encode()).hexdigest()
                      for c in codes}


def test_enrollment_needs_the_password_and_a_working_code(store, clock):
    _alice(store)
    with pytest.raises(MfaStateError):
        store.confirm_mfa_enrollment("alice", "123456")  # nothing started
    with pytest.raises(InvalidCredentialsError):
        store.begin_mfa_enrollment("alice", "wrong-password-123")
    secret = store.begin_mfa_enrollment("alice", ALICE_NEW_PW)["secret"]
    with pytest.raises(InvalidSecondFactorError):
        store.confirm_mfa_enrollment("alice", "000000")
    assert store.get_user("alice").mfa_enabled is False
    store.confirm_mfa_enrollment("alice", _code(secret, clock))
    assert store.get_user("alice").mfa_enabled is True
    with pytest.raises(MfaStateError):
        store.begin_mfa_enrollment("alice", ALICE_NEW_PW)


def test_enrollment_signs_out_password_only_sessions(store, clock):
    _alice(store)
    keep = store.create_session("alice").token
    store.create_session("alice")
    secret = store.begin_mfa_enrollment("alice", ALICE_NEW_PW)["secret"]
    store.confirm_mfa_enrollment("alice", _code(secret, clock), keep_token=keep)
    assert store.session_count("alice") == 1
    assert store.resolve_session(keep) is not None


def test_disable_needs_password_and_code(store, clock):
    _alice(store)
    secret, _ = _enroll(store, clock)
    with pytest.raises(InvalidCredentialsError):
        store.disable_mfa("alice", "wrong-password-123", _code(secret, clock))
    with pytest.raises(InvalidSecondFactorError):
        store.disable_mfa("alice", ALICE_NEW_PW, "000000")
    assert store.disable_mfa("alice", ALICE_NEW_PW, _code(secret, clock)) == "totp"
    assert store.get_user("alice").mfa_enabled is False
    assert store.recovery_codes_remaining("alice") == 0
    _, method = store.sign_in("alice", ALICE_NEW_PW)
    assert method is None
    with pytest.raises(MfaStateError):
        store.disable_mfa("alice", ALICE_NEW_PW, "000000")


def test_regenerate_replaces_codes_and_needs_an_app_code(store, clock):
    _alice(store)
    secret, old = _enroll(store, clock)
    with pytest.raises(InvalidSecondFactorError):
        store.regenerate_recovery_codes("alice", old[0])  # a recovery code is not enough
    new = store.regenerate_recovery_codes("alice", _code(secret, clock))
    assert len(new) == 10 and not set(new) & set(old)
    with pytest.raises(InvalidSecondFactorError):
        store.sign_in("alice", ALICE_NEW_PW, old[1])
    clock.advance(30)
    assert store.sign_in("alice", ALICE_NEW_PW, new[0])[1] == "recovery_code"


def test_admin_reset_clears_everything_and_signs_out(store, clock):
    _alice(store)
    _enroll(store, clock)
    store.create_session("alice")
    assert store.admin_reset_mfa("alice") is True
    assert store.get_user("alice").mfa_enabled is False
    assert store.session_count("alice") == 0
    assert store.recovery_codes_remaining("alice") == 0
    row = store._conn.execute("SELECT mfa_secret, mfa_pending_secret FROM users "
                              "WHERE username = 'alice'").fetchone()
    assert (row["mfa_secret"], row["mfa_pending_secret"]) == (None, None)
    assert store.sign_in("alice", ALICE_NEW_PW)[1] is None


def test_database_from_an_older_release_is_migrated(tmp_path, clock):
    path = tmp_path / "users.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE users (
            username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, roles TEXT NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0,
            must_change_password INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL,
            created_by TEXT, updated_at REAL NOT NULL, last_login_at REAL,
            failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until REAL);
    """)
    from vecshield_platform.api.users import hash_password
    conn.execute("INSERT INTO users (username, password_hash, roles, created_at, "
                 "updated_at) VALUES ('admin', ?, '[\"admin\"]', 1, 1)",
                 (hash_password(ADMIN_PW),))
    conn.commit()
    conn.close()
    store = UserStore(path, clock=clock)
    try:
        user, method = store.sign_in("admin", ADMIN_PW)
        assert (user.mfa_enabled, method) == (False, None)
        secret = store.begin_mfa_enrollment("admin", ADMIN_PW)["secret"]
        store.confirm_mfa_enrollment("admin", _code(secret, clock))
    finally:
        store.close()


# ---- API ------------------------------------------------------------------ #

def _app(store, audit, **kw):
    return create_app(config_store=ConfigStore(), serve_ui=False,
                      user_store=store, audit_log=audit, **kw)


def _login(c, username, password, otp=None):
    body = {"username": username, "password": password}
    if otp is not None:
        body["otp"] = otp
    return c.post("/auth/login", json=body)


def _admin_ready(c):
    assert _login(c, "admin", "admin").status_code == 200
    r = c.post("/auth/password", headers=CSRF,
               json={"current_password": "admin", "new_password": ADMIN_PW})
    assert r.status_code == 200, r.text
    return c


def _api_enroll(c, clock, password):
    r = c.post("/auth/mfa/setup", headers=CSRF, json={"current_password": password})
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = c.post("/auth/mfa/confirm", headers=CSRF, json={"code": _code(secret, clock)})
    assert r.status_code == 200, r.text
    clock.advance(30)
    return secret, r.json()["recovery_codes"]


def _actions(audit):
    return [e.action for e in audit.entries]


def test_login_round_trip_with_a_code(store, audit, clock):
    c = _admin_ready(TestClient(_app(store, audit)))
    secret, codes = _api_enroll(c, clock, ADMIN_PW)
    assert c.get("/auth/session").json()["user"]["mfa_enabled"] is True
    c.post("/auth/logout", headers=CSRF)

    r = _login(c, "admin", ADMIN_PW)
    assert r.status_code == 401
    assert r.json()["mfa_required"] is True
    assert c.get("/stores").status_code == 401  # no session yet

    r = _login(c, "admin", ADMIN_PW, "000000")
    assert r.status_code == 401 and r.json()["mfa_required"] is True

    r = _login(c, "admin", ADMIN_PW, _code(secret, clock))
    assert r.status_code == 200
    assert c.get("/stores").status_code == 200

    actions = _actions(audit)
    assert "auth.mfa_enrolled" in actions
    failed = [e for e in audit.entries if e.action == "auth.login_failed"]
    assert failed[-1].details["reason"] == "invalid_otp"
    assert audit.entries[-1].action == "auth.login"
    assert audit.entries[-1].details["second_factor"] == "totp"

    # Neither the secret nor any recovery code reaches the audit log.
    dumped = json.dumps([e.to_dict() for e in audit.entries])
    assert secret not in dumped
    assert not any(code in dumped or code.replace("-", "") in dumped for code in codes)


def test_recovery_code_login_is_audited(store, audit, clock):
    c = _admin_ready(TestClient(_app(store, audit)))
    _, codes = _api_enroll(c, clock, ADMIN_PW)
    c.post("/auth/logout", headers=CSRF)
    assert _login(c, "admin", ADMIN_PW, codes[3]).status_code == 200
    used = [e for e in audit.entries if e.action == "auth.recovery_code_used"]
    assert used and used[-1].details == {"remaining": 9}


def test_status_disable_and_regenerate_routes(store, audit, clock):
    c = _admin_ready(TestClient(_app(store, audit)))
    assert c.get("/auth/mfa").json() == {"enabled": False, "recovery_codes_remaining": 0,
                                         "policy": "off", "enrollment_required": False}
    r = c.post("/auth/mfa/setup", headers=CSRF, json={"current_password": "nope-nope-nope"})
    assert r.status_code == 401
    secret, _ = _api_enroll(c, clock, ADMIN_PW)
    assert c.post("/auth/mfa/setup", headers=CSRF,
                  json={"current_password": ADMIN_PW}).status_code == 409

    r = c.post("/auth/mfa/recovery-codes", headers=CSRF, json={"code": _code(secret, clock)})
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10
    clock.advance(30)

    r = c.post("/auth/mfa/disable", headers=CSRF,
               json={"current_password": ADMIN_PW, "code": "000000"})
    assert r.status_code == 401
    r = c.post("/auth/mfa/disable", headers=CSRF,
               json={"current_password": ADMIN_PW, "code": _code(secret, clock)})
    assert r.status_code == 200
    assert r.json()["user"]["mfa_enabled"] is False
    for action in ("auth.recovery_codes_regenerated", "auth.mfa_disabled"):
        assert action in _actions(audit)


def test_mfa_routes_need_a_console_session(store, audit):
    c = TestClient(_app(store, audit, admin_token="tok"))
    r = c.post("/auth/mfa/setup", headers={"Authorization": "Bearer tok"},
               json={"current_password": "x"})
    assert r.status_code == 400


def test_admin_policy_gates_unenrolled_admins_only(store, audit, clock):
    _alice(store)
    app = _app(store, audit, mfa_required="admin")
    admin = _admin_ready(TestClient(app))
    r = admin.get("/stores")
    assert r.status_code == 403
    assert r.json()["detail"] == "two-step sign-in set-up required"
    assert admin.get("/auth/session").json()["user"]["mfa_enrollment_required"] is True
    assert admin.get("/auth/mfa").status_code == 200

    viewer = TestClient(app)
    assert _login(viewer, "alice", ALICE_NEW_PW).status_code == 200
    assert viewer.get("/stores").status_code == 200

    _api_enroll(admin, clock, ADMIN_PW)
    assert admin.get("/stores").status_code == 200


def test_all_policy_gates_every_local_account(store, audit, clock):
    _alice(store)
    c = TestClient(_app(store, audit, mfa_required="all"))
    assert _login(c, "alice", ALICE_NEW_PW).status_code == 200
    assert c.get("/stores").status_code == 403
    _api_enroll(c, clock, ALICE_NEW_PW)
    assert c.get("/stores").status_code == 200


def test_policy_does_not_apply_to_bearer_tokens(store, audit):
    c = TestClient(_app(store, audit, admin_token="tok", mfa_required="all"))
    assert c.get("/stores", headers={"Authorization": "Bearer tok"}).status_code == 200


def test_policy_comes_from_the_environment_and_is_validated(store, audit, monkeypatch):
    monkeypatch.setenv("VECSHIELD_MFA_REQUIRED", "all")
    assert _app(store, audit).state.mfa_policy == "all"
    with pytest.raises(ValueError):
        _app(store, audit, mfa_required="sometimes")


def test_admin_resets_another_accounts_mfa(store, audit, clock):
    _alice(store)
    store.update_user("alice", roles=["viewer", "operator"])
    app = _app(store, audit)
    alice = TestClient(app)
    assert _login(alice, "alice", ALICE_NEW_PW).status_code == 200
    _api_enroll(alice, clock, ALICE_NEW_PW)

    assert alice.post("/auth/users/alice/mfa/reset", headers=CSRF).status_code == 403

    admin = _admin_ready(TestClient(app))
    r = admin.post("/auth/users/alice/mfa/reset", headers=CSRF)
    assert r.status_code == 200
    assert r.json()["user"]["mfa_enabled"] is False
    assert alice.get("/stores").status_code == 401  # signed out everywhere
    entry = [e for e in audit.entries if e.action == "auth.mfa_reset"][-1]
    assert (entry.actor, entry.target) == ("admin", "alice")
    assert entry.details["was_enabled"] is True

    assert admin.post("/auth/users/admin/mfa/reset", headers=CSRF).status_code == 409
    assert admin.post("/auth/users/nobody/mfa/reset", headers=CSRF).status_code == 404
    listing = admin.get("/auth/users").json()["users"]
    assert {u["username"]: u["mfa_enabled"] for u in listing} == {"admin": False,
                                                                  "alice": False}


# ---- JWT amr -------------------------------------------------------------- #

def _jwt(claims: dict, secret: str = "jwt-secret") -> str:
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    sig = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(sig)}"


@pytest.mark.parametrize("amr,ok", [
    (["pwd", "otp"], True), (["hwk"], True), ("mfa", True),
    (["pwd"], False), (None, False), ([], False),
])
def test_jwt_can_require_an_mfa_amr_claim(amr, ok):
    claims = {"sub": "carol", "exp": 4_000_000_000, "roles": ["viewer"]}
    if amr is not None:
        claims["amr"] = amr
    header = f"Bearer {_jwt(claims)}"
    assert JWTAuthenticator("jwt-secret").authenticate(header).subject == "carol"
    strict = JWTAuthenticator("jwt-secret", require_mfa=True)
    if ok:
        assert strict.authenticate(header).subject == "carol"
    else:
        with pytest.raises(AuthError):
            strict.authenticate(header)


def test_jwt_amr_requirement_from_environment(monkeypatch, store, audit):
    monkeypatch.setenv("VECSHIELD_JWT_REQUIRE_MFA", "1")
    c = TestClient(_app(store, audit, jwt_secret="jwt-secret"))
    base = {"sub": "carol", "exp": 4_000_000_000, "roles": ["viewer"]}
    weak = {"Authorization": f"Bearer {_jwt(base)}"}
    strong = {"Authorization": f"Bearer {_jwt({**base, 'amr': ['pwd', 'otp']})}"}
    assert c.get("/stores", headers=weak).status_code == 401
    assert c.get("/stores", headers=strong).status_code == 200
