# A verifier far behind never verifies an account by Prove
> Summary: A Prove carries at most `MAX_ROTATIONS` of the proving chain (the newest that fit, `session::rotations`); a verifier holding the account's record but lacking more than that never takes the newest by Prove and learns them only by syncing data the chain travels with.
> Priority: low
> Tags: sync, engine

Stage A4 (notes/redesign-plan.md) deletes the account signing chain a Prove carries; read again there (a proof of an owner key, spec/sync-opens.md §2).

- The prover does not know what the verifier holds, so it sends the newest rotations of `AccountView::proving_chain` that fit. A verifier holding the chain up to them takes them all; one lacking older ones keeps nothing of them (they would pend; nothing carries them).
- At infinity (a long-lived account, a fresh verifier) Prove proves nothing; sync still delivers the chain as certificates of any sync ID it shares with the account.
- Candidate if it matters: the verifier names what it holds of the account (heights per head) in its Hello, or the prover sends from the newest epoch the verifier is known to hold (peer record). Both add wire or record state for a rare path.
