# ADR 0004: Two-step sign-in for local accounts

Status: accepted (2026-11-14)

## Context

[ADR 0002](0002-local-accounts-and-sessions.md) gave the console local accounts
that sign in with a username and password. One password protects the `admin`
role, which can grant roles, reveal raw values and erase data. Frameworks that
deployments are assessed against, SOC 2 among them (CC6.1, logical access),
expect privileged access to need more than one factor. Auditors test for it.

Organizations with an identity provider can enforce MFA there, but the console
must also work in air-gapped and self-hosted installs that have no identity
provider. ADR 0002 makes the same point.

## Decision

1. **TOTP authenticator apps** (RFC 6238: SHA-1, 6 digits, 30-second steps).
   Every common authenticator app supports these, and they work offline.
2. **Maintained libraries, not our own OTP code.**
   [pyotp](https://github.com/pyauth/pyotp) (MIT) generates and checks codes
   and builds the `otpauth://` URI. [segno](https://github.com/heuer/segno)
   (BSD) renders the URI as an SVG QR code on the server, so the hand-written
   console needs no JavaScript QR library. Both are pure Python with no
   dependencies of their own. `vecshield_platform/api/mfa.py` is a thin layer
   over them.
3. **Replay protection** is the one piece pyotp does not provide, because it
   keeps no state. A code is accepted for the current step and one step either
   side, to allow for clock drift. The step it matched is stored as
   `mfa_last_step`, and any code for that step or an earlier one is refused.
   Checking and recording the step happen in one transaction, so two
   concurrent sign-ins cannot both use one code.
4. **Sign-in is one endpoint, two attempts.** `POST /auth/login` with a right
   password and no `otp` answers `401 {"mfa_required": true}`. That attempt is
   handed back and does not count toward the lockout. The console then asks for
   the code and sends the password again with `otp`. A wrong or reused code
   counts toward the same lockout as a wrong password (ADR 0002 §7). No
   half-signed-in session exists between the two attempts.
5. **Recovery codes.** Turning on two-step sign-in returns ten single-use
   codes of 80 random bits each. This is the only time they are shown. Only
   their SHA-256 is stored, as with session tokens, so a slow KDF is not
   needed at this entropy. A code is marked used only while it is still
   unused (`UPDATE ... WHERE used_at IS NULL`), so it works exactly once.
   Using one is audited along with how many remain.
6. **Enrollment needs the password.** `POST /auth/mfa/setup` takes the current
   password, so a borrowed session cannot attach someone else's authenticator.
   The secret stays pending until `POST /auth/mfa/confirm` sees a working code.
   Turning it on signs the account out of its other sessions, which were opened
   with a password alone.
7. **Changing it needs proof.** Turning it off needs the password and a code;
   either a TOTP or a recovery code is accepted. New recovery codes need a
   code from the app itself. A wrong password or code counts toward the
   lockout.
8. **Admin reset** for a lost device. `POST /auth/users/{username}/mfa/reset`
   (admin) clears the factor and the recovery codes and signs the account out
   everywhere. An admin cannot reset their own: they turn it off from
   Settings, which asks for the password and a code.
9. **Policy.** `VECSHIELD_MFA_REQUIRED` / `serve --mfa-required` is `off`
   (default), `admin`, or `all`. A local account that the policy covers but
   that has no factor signs in to a restricted session. Every protected route
   answers `403 two-step sign-in set-up required`, and the console shows the
   set-up screen. A forced password change comes first. The Helm chart
   defaults to `admin`. `serve` warns when it binds beyond localhost with
   local accounts and the policy `off`.
10. **Tokens and JWTs.** The policy applies to console sessions. Static tokens
    are automation credentials and are unchanged. An identity provider proves
    MFA through the RFC 8176 `amr` claim: with `VECSHIELD_JWT_REQUIRE_MFA=1`,
    a JWT is accepted only if `amr` includes `mfa`, `otp`, `hwk` or `swk`.
11. **Audit.** `auth.mfa_enrolled`, `auth.mfa_disabled`, `auth.mfa_reset`,
    `auth.recovery_codes_regenerated`, `auth.recovery_code_used`, and
    `auth.login_failed` with reason `invalid_otp`. `auth.login` records
    `second_factor`. Secrets and codes are never logged.

## Alternatives considered

- **Our own RFC 6238 implementation on `hmac`.** It is short to write, but
  security code is better taken from a widely used, maintained library than
  written again.
- **WebAuthn / passkeys.** These resist phishing, which TOTP does not. But they
  need a browser ceremony in the console, origin and RP-ID configuration, and
  a CBOR/COSE dependency. They also cannot be set up from a phone alone on a
  server without a public name. They are worth adding later beside TOTP.
- **Email or SMS codes.** These need an outbound mail or SMS path that
  air-gapped installs do not have, and SMS is a weak factor.
- **A pending "password ok" session between the two steps.** That is one more
  token type to issue, expire and revoke. Sending the password again on the
  second attempt keeps one code path, and the password already travels over
  the same channel on the first attempt.
- **Encrypting the TOTP secret at rest.** The server must read the secret to
  check a code, so the key would have to sit beside the database. The secret
  lives in `users.db`, which is created `0600` like the password hashes and
  session digests. Encrypting the whole state directory is a separate concern
  and belongs to the deployment's volume encryption.

## Consequences

- Console sign-in can meet a "MFA for privileged access" control, and the
  audit log shows who turned it on, who turned it off and who reset it.
  `GET /auth/users` reports `mfa_enabled`, so an access review can list the
  accounts without it.
- Someone who reads `users.db` can generate codes. Back it up and protect it
  like the rest of the state directory.
- A correct password now gets a different answer (`mfa_required`) than a wrong
  one, but only for accounts with a second factor. Wrong passwords still count
  toward the lockout, so this does not add guesses.
- Losing the device and every recovery code locks a person out until an admin
  resets their factor. If the last admin loses both, the recovery path is the
  one ADR 0002 documents for a lost password.

## Migration and reproduction impact

- `users.db` gains four columns on `users` and a `recovery_codes` table. Both
  are added on open, so existing databases keep working and every account
  starts with two-step sign-in off.
- The default policy is `off`, so upgrading changes nothing until an operator
  sets it. A Helm upgrade adopts the chart default `admin`: admins are taken
  to set-up at their next sign-in.
- `pyotp` and `segno` are new core dependencies.
- `UserStore.authenticate()` keeps its signature and gains an optional `otp`.
  `sign_in()` also says how the second factor was met. `Principal` gained a
  defaulted `mfa_enabled` field.
