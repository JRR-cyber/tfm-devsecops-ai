"""remote-property-injection in lib/insecurity.ts (tokenMap[token] / idMap[id]).

put() is only called from updateAuthenticatedUsers after jwt.verify succeeds (or
at login with a server-issued token), so token is always a valid signed JWT and
id comes from the verified payload. GATE check: a polluting token ("__proto__")
is not a valid JWT, so it is not authenticated and put() is never called with it.
"""

import json
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    req = urllib.request.Request(f"{base}/rest/user/whoami", headers={"Cookie": "token=__proto__"})
    with urllib.request.urlopen(req) as res:
        user = json.load(res).get("user", {})
    # Not authenticated: no real user fields (the forged token was rejected).
    rejected = not user.get("email") and not user.get("id")
    return rejected, f"forged token not authenticated: {rejected} (user={user})"
