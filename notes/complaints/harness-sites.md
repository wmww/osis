# harness-sites
> Summary: Footguns met moving engine hand deliveries to carried packages and adding the sim's history oracle.

- Pushed once with `python3 tools/policy.py --baseline; ... && git push`: the `;` dropped policy's exit and a violation reached main (fixed in the next push). Chain policy with `&&` into the push, always.
- `packages_for(from, to)` reads `to`'s sync set before delivery: where the delivered list itself carries a grant, content of the newly granted thing is missing. `LocalPeer::packages_to` (copy + sync) is the replacement there; `packages_to_peer` for a node apart.
- A 5-line-window rewrite picked a receiver for lists later handed to a second peer too (rotation/tests.rs, tests_signing.rs): check every receiver of a `let` list by hand.
