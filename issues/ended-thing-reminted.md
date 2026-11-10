# Anyone holding a record can keep its thing from ending
> Summary: A minting (`created.0`) needs no authority, so anyone holding a thing's record (every reader of a dependent's label, by record blobs) can mint it again at any `ts`: a durable minting keeps an expiring thing existing or brings it back, and a `nobody` (or another's `author`) one keeps it from ending by purge. It carries no content. Stated as a limit in spec/commits.md §5 Ending; Tess to accept it or ask for a rule.
> Priority: low
> Tags: engine, permissions, security, tess-call

- What users see: an ended thing (a disappearing message, a purged item) can read again as existing but empty; its content still expires and is purged as before, and only copies still held come back.
- Why mintings escape "nobody writes after its ending": the ending is where every minting ended, so a later one would decide it by arrival, and an order-free cut lets a backdated minting expiring early end a thing before its real creation (data loss). notes/expiry-creation-design.md (Limit).
- Rejected: a minting judged as a write on its thing. It loses a removed writer's creation its removal's frontier omits (addenda vouch for content, not `created.0`; letting them vouch for it looped, `osis` `sync::removal_from_partial_node_keeps_unheld_edits_spec_permissions_5_2`), and still leaves writers able to do the same.
