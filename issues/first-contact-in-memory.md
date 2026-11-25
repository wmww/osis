# A restart loses a public redeem and a new node's dial hints
> Summary: two first-contact states live in memory only: a public link's redeem (`inbox/links.rs` `redeem_public`; a private link's redeem is a durable row) and the pairer's dial hints a new node was given (`Osis::dial_hints`, osis-sync `inbox/mod.rs`); a restart before the join or before the account's `dial.0` arrives forgets them, and nothing tells the app.
> Priority: low
> Tags: sync

- Property: what the user asked for (redeem a link, pair a node) completes or fails visibly; one mechanism for both link kinds.
- Minimal worlds: (a) redeem a public link, restart before the target is held: the redeem is forgotten, while a private link's goes on after the restart (its `Pending` row). (b) pair a node configured to dial nothing, restart before A's `dial.0` arrives: the node knows no address of the account's nodes.
- Options: keep both as durable rows like the private redeem's (one row each, dropped at the join or give-up); or state that a restart ends them and make the API say so (the redeem future fails, pairing returns an error the app retries). The first is one mechanism.
