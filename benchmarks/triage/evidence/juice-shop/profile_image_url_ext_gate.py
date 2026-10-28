"""FP guard for routes/profileImageUrlUpload.ts:29 path-injection (GATE).

CodeQL traces req.body.imageUrl -> ext -> the write path
`uploads/${id}.${ext}`. But ext is sanitized by a 5-value allowlist:
    ['jpg','jpeg','png','svg','gif'].includes(last.toLowerCase()) ? last : 'jpg'
so the attacker-controlled extension cannot traverse or become anything else.
The numeric id is the server-side user id, not part of the traced flow.

GATE: upload an imageUrl whose extension is a non-image/traversal token (.sh);
after a fresh login the stored profileImage path ends in an allowlisted image
extension (coerced to .jpg), never .sh. A benign .png URL is preserved as .png,
showing it is an allowlist, not a blanket rewrite.
"""

import json
import urllib.request
import uuid

USER = {"email": "jim@juice-sh.op", "password": "ncc-1701"}
ALLOWED = ("jpg", "jpeg", "png", "svg", "gif")


def _multipart(fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = "----tfm" + uuid.uuid4().hex
    body = b""
    for key, value in fields.items():
        body += (f"--{boundary}\r\n"
                 f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                 f"{value}\r\n").encode()
    body += f"--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def _login(base: str) -> str:
    req = urllib.request.Request(f"{base}/rest/user/login", data=json.dumps(USER).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req) as res:
        return json.load(res)["authentication"]["token"]


def _upload_and_read(base: str, url_extension: str) -> str:
    token = _login(base)
    urllib.request.urlopen(urllib.request.Request(f"{base}/rest/user/whoami",
                                                  headers={"Cookie": f"token={token}"}))
    # loopback target so fetch succeeds; the chosen extension rides in the query.
    image_url = f"http://127.0.0.1:3000/rest/admin/application-version?z=tfm.{url_extension}"
    body, ctype = _multipart({"imageUrl": image_url})
    urllib.request.urlopen(urllib.request.Request(f"{base}/profile/image/url", data=body,
                                                  headers={"content-type": ctype,
                                                           "Cookie": f"token={token}"}))
    # a fresh login reloads the user data (incl. profileImage) from the database.
    token2 = _login(base)
    with urllib.request.urlopen(urllib.request.Request(f"{base}/rest/user/whoami",
                                                       headers={"Cookie": f"token={token2}"})) as res:
        return json.load(res)["user"].get("profileImage", "") or ""


def exploit(base: str) -> tuple[bool, str]:
    malicious = _upload_and_read(base, "sh")
    benign = _upload_and_read(base, "png")

    coerced = malicious.lower().rsplit(".", 1)[-1] in ALLOWED and not malicious.lower().endswith(".sh")
    preserved = benign.lower().endswith(".png")
    ok = coerced and preserved
    return ok, (f"malicious .sh -> {malicious!r} (coerced={coerced}); "
                f"benign .png -> {benign!r} (preserved={preserved})")
