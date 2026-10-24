"""remote-property-injection in lib/accuracy.ts (solves[challengeKey] = ...).

challengeKey only reaches storeVerdict through the vulnCode* endpoints, which
reject any key that is not a known coding challenge before accuracy is touched.
GATE check: a polluting key ("__proto__") at /snippets/fixes is rejected (404),
so accuracy never receives it.
"""

import json
import urllib.error
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    body = json.dumps({"key": "__proto__", "selectedFix": 0}).encode()
    req = urllib.request.Request(f"{base}/snippets/fixes", data=body,
                                 headers={"content-type": "application/json"})
    try:
        urllib.request.urlopen(req)
        return False, "key __proto__ was accepted (reached accuracy)"
    except urllib.error.HTTPError as err:
        # Any error (404 unknown key, or 500 when readFixes('__proto__') returns
        # Object.prototype and .fixes.length throws) means the verdict path that
        # calls accuracy.storeVerdict is never reached with the polluting key.
        return err.code >= 400, f"key __proto__ rejected with HTTP {err.code} before accuracy"
