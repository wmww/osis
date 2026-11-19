# Content of a needed thing outside the node closure depends on arrival order
> Summary: A thing outside the node closure that a held thing needs keeps its content if it never entered the closure, but loses it if a pass let it in for a while and then released it. So two nodes holding the same commits show different values. spec/commits.md §5 contradicts itself here. Fails osis-engine `order::held_set_decides_plain`. Needs a design decision.
> Priority: normal
> Tags: engine, spec, tess-call

## The contradiction
spec/commits.md §5 What a held thing needs: a thing outside the node closure "is kept (its record, every held commit on it, the secrets the node holds of it) only while a held thing needs it". The same section, A released thing (and spec/sync-set.md §3 "Nothing of R stays: its content"), says a released thing keeps only "its record, and its role commits on that chain" while it is needed. Everything else goes.

The engine does what both sentences say. `Engine::settle_needs` keeps a needed thing whole. `Engine::released` forgets a still-needed thing's content (`forget::forget`) and keeps its record and role-class state. A thing can end up outside the closure and needed in two ways:
- **never entered the closure**: content parts that arrive on it apply and stay;
- **entered it for a while during a pass, then left**: the pass end releases it, and its content goes as never received. The node does not count that content missing, and no pull anew brings it back. `units::refetch` pulls anew only for a thing whose record the node does not hold, and this thing's record stays because it is still needed.

This breaks the section's own rule: "what a node holds of things outside its closure at quiet is a function of what it holds, never of arrival order".

## How it shows (`held_set_decides_plain`)
Shrunk history (seed 874943289203, `Cfg { all_up_to: 4, random: 6, partial: 6, split: Twins::First(2), clock: 2, reopens: 2, withhold: true, model: true, ..ORDERS }`):

`[RecordOnly { by: 0, under: None }, RemoveFlow { by: 0, t: 1, holder: 0, lower: false }, a(RemoveFlow { by: 1, t: 1, holder: 0, lower: false }), a(RemoveFlow { by: 2, t: 0, holder: 2, lower: false }), a(RecordOnly { by: 0, under: Some(0) }), a(GrantFlow { by: 1, t: 1, holder: 3, role: Admin }), Sync { from: 0, to: 1 }, a(Message { by: 1, t: 1, v: 5 })]`

In words:
1. Carol removes herself from G.
2. Alice makes thing U with mint admin G, adding a strong to U in G's `holds.0` in the same commit.
3. Carol's removal makes that strong write invalid, so at quiet U is outside the node closure. U is still needed, because an edge write on U names G as holder.
4. Bob writes a message on U.

In reversed order, the commits arrive before Carol's account record. Until the record arrives, Carol's removal cannot be judged, so Alice's strong counts and U is in the closure. Then the record arrives, U leaves the closure, and the pass end releases U. Bob's message, applied in between, goes with the release. The node that keeps every body, and every node given Carol's record first, never has U in the closure and shows the message.

Seed 367121598791 (Addenda, `t:reg.0`, shrunk to 27 steps) and seed 430540858112 (Purges, `t:text.0`, not shrunk) fail the same way. Differential check: with `released` skipping every thing a held thing still needs (option B below), all three replay seeds pass.

## Options
- **A: outside the node closure, a needed thing is held only as certificates**: its record, its role commits on the chain, and its secrets. Content parts on it go at the pass end as never received, the same as at a release, whether or not the thing was ever in the closure. This matches A released thing, sync-set §3, and spec/sync-judgement.md §1 Sealed sections: a real node never opens content of a thing outside its closure, so only plaintext test delivery can apply such content at all. It needs two engine changes:
  1. the pass end strips content from needed-only things (for example, content applying outside the closure notes the thing for release);
  2. a thing entering the closure with its record held but content forgotten is pulled anew (`refetch` triggers on more than "record not held"). The spec sentence in sync-judgement §3 Dropped bodies changes to match.
- **B: a release keeps a still-needed thing whole.** Content goes only once nothing needs the thing. This is a small engine change: `released` drops only what nothing needs. But it contradicts sync-set §3, and a node keeps content of a thing it lost access to for as long as, say, an edge write on it names a held holder.

Recommended: A. It matches the area's own statement that only nodes holding a thing read its parts. B is the smaller diff but keeps content the release rule says goes.

Possibly related, not checked by a test: a released thing whose record stays needed, entering the closure again, is never pulled anew (`refetch` returns early because the record is held). So content dropped at the release may never come back, even under the current rules.

Replay: `OSIS_ORDER_SEED=874943289203 OSIS_ORDER_LEN=60 cargo test -p osis-engine --test it -- --ignored --exact order::held_set_decides_plain` (also seeds 430540858112 and 367121598791; `OSIS_ORDER_SHRINK=1` with `OSIS_SHRINK_MATCH='after the sync exchange: shows other than the node keeping every body'` shrinks it).
