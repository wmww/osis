# Expired links are never finalized: seed holders join later by backdating
> Summary: spec/permissions.md §9 says a link's `until` (like a single-use redemption) is finalized by a sharer device's plain removal of L, which audits L's later-backdated invite grants away. `Osis::upkeep_links` finalizes single-use links only, so after `until` anyone holding the link text writes an invite grant signed as L with a `ts` before `until` and becomes a permanent member of K (and so reads the target).
> Tags: security, osis, permissions

Severity: high (link expiry is a promise the user relies on; link texts travel in chats and mail).

Where: core/osis/src/share.rs:566 (`upkeep_links` filters `m.single_use`); the `until` case only marks a direct link `ended` and rotates the dialable key (share.rs:585-600). notes/permissions.md "Also checked" already records that "a backdated join after `until` ... stands until the sharer's removal of L drops it": the removal is never written.

Scenario: sharer makes a 1-day read link to a doc. A week later someone finds the link text, derives L, opens K's label (L's static entry is gone from new steps, but its edge is still in K's roster and it holds K's older epochs), and signs an invite grant for its own actor with `ts` = expiry - 1 s. The timeline applies it (L held invite then; a demotion by `until` audits nothing). Every later rotation of K boxes the newcomer as a current member.

Fix direction: finalize at `until` too: when a made link's L edge is past `until`, write `finalize_link` (explicit removal with frontier), as for single use; arm it on open and on the clock (the edge's `until` as a timer). Consider doing it in the engine (any sharer device, not just the one that made it, holds the seed thing).
