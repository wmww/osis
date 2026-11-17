# Anyone holding a record can keep its thing from expiring or a non-admin's purge
> Summary: A minting (`created.0`) needs no authority, so anyone holding a thing's record (every reader of a dependent's sync ID, by record blobs) can mint it again at any `ts`: a durable minting keeps an expiring thing existing or brings it back, and one purgeable by `admin` alone keeps a non-admin's purge (by `author_or_admin` or `writer`) from destroying it. It carries no content. Stated as a limit in spec/commits.md §5 Destruction and accepted by Tess. An admin's purge reaches every minting (`nobody` is fixed retention's alone).
> Priority: low
> Tags: engine, permissions, security

- What users see: a disappearing message, or an item its author or a writer purged, can read again as existing; its content still expires and is purged as before, and only copies still held come back. Back, it is live: its roster stands and its writers write it again, writes stamped after the destruction included, alike at every node.
- Expiry half: needs another rule. The record carrying the expiry is rejected (`Write::create` returns the tid before the commit's expiry is resolved).
- Non-admin purge half: a destroying request reaching every minting whatever its retention needs a rule for whose right counts (the witness's moves with arrivals). Making `created.0` fixed `admin` closes it but drops author- and writer-destroyable things.
- Not a mark for expiry: an expiry has no verdict over other mintings to keep, and a mark set at `T` would take or refuse a durable minting by its arrival around `T`, so honest nodes split for good on any minting in transit at its expiry. The rule belongs at the root: who may mint again.
- Why mintings escape "nobody writes after its destruction": the destruction is where every minting was dropped, so a later one would decide it by arrival, and an order-free cut lets a backdated minting expiring early destroy a thing before its real creation (data loss). notes/expiry-creation-design.md (Limit).
- Rejected: a minting judged as a write on its thing. It loses a removed writer's creation its removal's frontier omits (addenda vouch for content, not `created.0`; letting them vouch for it looped), and still leaves writers able to do the same.
- Test: engine `validity::no_minting_keeps_a_thing_from_its_admins_purge_spec_commits_5` (the admin half).
