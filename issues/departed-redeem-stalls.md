# A node removed from a thing never redeems a public link to it
> Summary: A node whose account was removed from X redeems a public link to X and stays pending for good: a source judging it departed shows it no public entry (shown at no epoch, so the Departed rule keeps it out), and once that is fixed its own lost-access rule drops the secret the entry box gave before it holds the public's grant.
> Priority: normal
> Tags: sync, engine

Repro: osis-sync `differential::repro_a_departed_node_redeems_a_public_link` (node 1 makes X, grants node 0's account write, node 0 holds it; node 1 makes X public and removes node 0's account in one run; node 0 then redeems a public link to X: `Pending`, reading nothing; the reference reads X). Full-size differential seed 74's class.

Why, two blocks:
- spec/sync-opens.md §4 Departed: a departed peer opens only by a credential at an epoch covering every departure; the public entry is shown at none (`holds.rs` `node_creds`). It carries the head's current read epoch, which covers: showing it at the current read epoch (tried) lets the open happen.
- `rotation::lost` judges a held secret no role covers "over-held" once a loss is seen (the account's removal held), and drops it before the open's role entries bring the public's grant (spec/permissions.md §3 Lost access). A fresh redeemer sees no loss and keeps the secret. The public's secrets are every party's (spec/permissions.md §1), so dropping one protects nothing; but the node learns that the secret is the public's only from the step's entry box (an admin's word that the public reads X), not from a role commit it holds.

Candidates: count a secret an open (public) entry box gave as covered while the step it came from lists the public entry (the head's word, as a store's head listing the public already gives its box, spec/sync-set.md §5), or take the open's role entries before judging the loss.
