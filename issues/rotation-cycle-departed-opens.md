# rotation_holds seed: a party reading a holder actor only through a key cycle opens its removal's epoch
> Summary: Seed 618244500061 of `rotation::tests_property::rotation_holds_large_spec_crypto_4` (fails on main too): peer 3 reads actors 1 and 2 only through actor 0 (cycle 0 -> 2 -> 1 -> 0, holder grants Admin, Write, Write), is removed from actor 0, and opens that removal's Read epoch n5, sealed to actor 1 at the keyset it held through the cycle. Unknown yet whether this is the stated hidden-grant cycle limit (spec/crypto.md §4 Holder actors) or a real leak.
> Priority: normal
> Tags: security, tests, rotation

Replay: `OSIS_ROTATION_START=618244500061 OSIS_ROTATION_SEEDS=1 cargo test -p osis-engine --lib -- --ignored --exact rotation::tests_property::rotation_holds_large_spec_crypto_4` (about 2 s).

What a probe showed (peer 0's view when it made n5):
- actor 0 holders: peer 0 Admin, actor 1 Write, peers 1, 2 Read, peer 4 Write; actor 1: peer 0 Admin, actor 2 Read; actor 2: actor 0 Admin, actor 1 Write, peers 1, 2 Admin. Peer 3 holds no edge on actors 1 or 2 there.
- n5 boxes actor 1 at its Read n2, which peer 0 made in the withheld step (20 commits withheld) with peer 3 not below: peer 3 then still read actor 1 through actor 0 -> actor 2. Peer 3 holds actor 1 Read n2 and both n2 forks of actor 2 (made by peers 1 and 2, also with peer 3 not below).
- The check's `met_unlimited` opens n5: actor 1 Read n2 is in the peer's base (held rightly when made), so the excused box (actor 1 n2 to actor 2) is not its only way.
Questions: which grant of the cycle is keyless at peer 0 (spec/crypto.md §4 Key access), and should peer 0's blocked walk at n5 (it holds actor 1 n2's secret) have left actor 1 out, since actor 1 n2 is held by a party whose only path ran through actor 0? If the cycle limit applies ("a party removed from an actor on it may open the other actors' epochs so sealed until a writer holding every grant of the cycle and its keysets has rotated them"), the oracle needs that excuse computed from the history; otherwise the walk misses a departure that reaches back into A through the cycle.

Reviewer read (not triaged further): likely a real leak, not the stated cycle limit. What opens is actor 0's own n5, the actor peer 3 was removed from, at a node holding every grant of the cycle; spec/requirements.md Permissions limits a cycle only to "the other actors' new content". The path back into actor 0 runs actor 1 n2 -> actor 2's box -> actor 0's pre-removal keyset, which n5 itself supersedes: Seal's stale-box walk cannot see that while n5 is being made, so the removal's own rotation seals actor 1 at n2.
