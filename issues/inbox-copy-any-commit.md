# Inbox copies store any valid commit a stranger sends under the home label
> Summary: `inbox_copies` places a certificate copy, under the actor's home label and stamped by every writer device, of every valid commit an opened inbox blob carries, not only one about the actor. A stranger with the inbox deposit seed gets arbitrary content stored for good outside the deposit budget; with a short prefix expiry on the inbox blob the budget refills at once.
> Tags: security, node, sync

Severity: medium (storage DoS of a person's home label, synced by all its devices; breaks spec/requirements.md "Read access never allows storing arbitrary content there").

Where: core/node/src/sync/pass.rs:1561 `inbox_copies`: the only checks are that the commit is applied, its carried parts are valid, and no entry holds it yet; then `place_certificate_in(g, &c, &ais)` for every part (and `/created`, `/label` of touched things named in the payload). Nothing checks that the commit is a membership commit about `g` (an edge whose member is `g`, a re-seal or rotation boxing `g`) by an admin of its target.

Scenario: the deposit seed of a person's home label is in its `/keys`, which travels as a chain certificate under every label its devices write, and to contact-card holders. A stranger makes, with its own node, a self-contained valid commit (creates a thing, writes a large value; or many chunked parts), seals it as an inbox blob to the person's read KEM key, deposits it with prefix expiry a minute ahead. Each device opens it, applies it (valid: the stranger owns the thing), and uploads a stamped copy; the blob expires, freeing the budget; repeat. Certificate copies are must/may-hold (labeling/converge.rs), so nobody deletes them.

Fix direction: copy only commits that spec/sync.md §3 describes (a membership commit whose edge, re-seal or rotation boxes concern the inbox actor, by an author with admin on the target at its `ts`), only those parts, with a size bound; senders' expiry is not trusted (copy nothing from a blob whose expiry is far below `INBOX_LIFETIME`). Spec §3 could state the copy rule explicitly.
