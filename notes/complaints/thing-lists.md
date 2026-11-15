# thing-lists
- The issue framed it as a list-blob placement question (rotator never seals, or receivers never hold); both were fine. The real cause was a level below: the account's rotation ended S between the two nodes (closed-epoch proof), so nothing of S crossed. A trace grep for `Lost` on S found it in minutes; worth trying before reading list code.
- A sibling of a rotator loses its home and its new seed (issues/sibling-rotation-drops-home.md): found while writing the sibling re-prove test, which cannot land until it is fixed.
- flows:: tests that rotate accounts cost 15-40 s each; the new driver test (contacts fixture) is ~1 s.
- `World::power_off` cuts without telling peers, so a connection to a powered-off node looks live until something closes it; once the re-prove closes it, the peer is redialed each `REDIAL_MS` for the rest of a long run (writers_of_two_accounts: 1 100 -> 9 500 deliveries, cap raised).
