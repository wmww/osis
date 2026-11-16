# D's ticket for a thing kept unread can box a forged secret alone
> Summary: A node keeping T unread writes D's ticket at the highest-epoch sync secret it holds of T, whatever ticket gave it; a ticket with a made-up higher epoch held when D's ticket is written puts only the forged secret in D, so a sibling entering T by D's tickets holds no secret a step of S bears.
> Priority: normal
> Tags: engine, sync, security

- `flows::inbox::held_by` gives every held sync secret of T when no read secret is held; `make_ticket_under` boxes the max by epoch, and `write_account_ticket` removes D's tickets of that role at a lower epoch whatever their sync ID. spec/sync-set.md §1 The account's tickets allows it ("any sync secret of T it holds").
- Anyone holding the account's public record can box such a ticket; it needs only to be held where the walk finds it (a writer of a held thing, an inbox fire once the strong exists).
- Test: engine `sync::tests_tickets::a_forged_sync_ticket_keeps_the_genuine_one_in_ds_tickets_spec_sync_set_1` (ignored; its forged-first arm fails: D holds only the forged epoch).
- Boxing every held secret instead grows D by every rotation and keeps forged secrets for as long as the strong (D's tickets are held tickets, so each keeps itself).
- Candidate rule: for a node keeping T unread, a sync secret counts as established once a step of S's own path bears its sync key (spec/sync.md §3 already makes that the only thing that keeps S). D's ticket boxes the newest such secret per sync ID, and replaces only D's tickets of the same sync ID. That also states spec/crypto.md Uses without its kept-unread exception. Needs the engine to read which held sync key S's stored path bears.
