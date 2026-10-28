"""FP guard for routes/profileImageFileUpload.ts:42 http-to-file-access (GATE).

CodeQL flags the uploaded request body (req.file.buffer) being written to
`uploads/${id}.${ext}` with fs.writeFile. But the handler rejects anything that
is not an image before the write: fileType.fromBuffer(buffer) must succeed and
uploadedFileType.mime must start with 'image', otherwise it returns 415/500. The
stored extension is the magic-byte-detected image type, and the id is the numeric
user id, so the attacker controls neither the path nor an arbitrary content type.

GATE: a non-image upload is rejected (status >= 400); a valid PNG is accepted
(the handler redirects, 302). So the content written is constrained to detected
images under a server-chosen path.
"""

import json
import struct
import urllib.error
import urllib.request
import uuid
import zlib

USER = {"email": "jim@juice-sh.op", "password": "ncc-1701"}


def _png() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
            + chunk(b"IEND", b""))


def _multipart_file(content_type: str, filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = "----tfm" + uuid.uuid4().hex
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def _upload(base: str, token: str, content_type: str, filename: str, data: bytes) -> int:
    body, ctype = _multipart_file(content_type, filename, data)
    req = urllib.request.Request(f"{base}/profile/image/file", data=body,
                                 headers={"content-type": ctype, "Cookie": f"token={token}"})

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a):  # don't follow the 302 success redirect
            return None
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        return opener.open(req).status
    except urllib.error.HTTPError as err:
        return err.code


def exploit(base: str) -> tuple[bool, str]:
    login = urllib.request.Request(f"{base}/rest/user/login", data=json.dumps(USER).encode(),
                                   headers={"content-type": "application/json"})
    with urllib.request.urlopen(login) as res:
        token = json.load(res)["authentication"]["token"]
    urllib.request.urlopen(urllib.request.Request(f"{base}/rest/user/whoami",
                                                  headers={"Cookie": f"token={token}"}))

    non_image = _upload(base, token, "text/plain", "evil.txt", b"this is not an image")
    png = _upload(base, token, "image/png", "ok.png", _png())

    ok = non_image >= 400 and png in (200, 302)
    return ok, f"non-image rejected (HTTP {non_image}); valid PNG accepted (HTTP {png})"
