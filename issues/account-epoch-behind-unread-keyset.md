# An ignorant account epoch behind a keyset the sealer cannot open
> Summary: a node of P knowing a removal from P's devices actor seals a holder actor T at a keyset of T whose secret it lacks; that keyset boxes P at an epoch minted by a node ignorant of the removal (seed under D's epoch the removed node opens). The box walk (`rotation::blocked_epoch`) stops at epochs whose secret the node lacks, so the removed node opens what the knowing node writes. On main before and after the descent rule.
> Priority: normal
> Tags: security, keys, engine

## Shape
As osis-engine `an_ignorant_fork_ordered_after_a_removal_covers_nothing_spec_crypto_4`, but N3 (peer 2) never receives N2's commits (`n2`, r2 among them): it holds L's removal, r1 and T's rotation `rt` boxing P at r2. It cannot open T at `rt` (only through r2's seed), so the walk does not pass `rt`; T has no departures it knows, so `rt` is not blocked by order either. N3's rotation of X seals T at `rt`; L opens X's new epoch (r2's seed, then T, then X). Reproduced by a probe test in review (the test body above, `send(&mut lp, 3, 2, &n2)` dropped).

## Direction
The box keys (holder, holder's epoch) are state, readable without the epoch's secret (`members::stale_at` reads them so). A box to this node's own account at an epoch it cannot show covers a removal it knows (not held, or held and uncovered) blocks the keyset boxing it, at any depth, secret held or not; the node learns r2 from D's labels and T's next keyset from T's, so it re-seals once either moves. Decide with issues/keys-depth0-rethink.md (what a node judges past what it holds).
