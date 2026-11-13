# A party removed below a holder actor keeps reading past the knowing rotation
> Summary: Confirmed leak, needs Tess: W, removed from X2 below holder actor X1 of G where G's writers cannot see it, still counts as a writer of X1 there. It can extend X1 past X1's knowing keyset, prove X1 at a made-up keyset, or backdate its rotation of G, and G's admin then writes under W's epoch after X1's knowing rotation reached it. That breaks the spec/requirements.md Permissions limit. No rule a node can judge from what it holds closes all three.
> Priority: normal
> Tags: security, keys, engine, tess-call

## Shape
G <- X1 <- X2 <- {W (write)}. B administers X1 and X2 and does not sync G. A administers G and syncs only G. B removes W from X2 and rotates X2 and X1 (X1's keyset k1 is the knowing one). A never sees the removal, which lives in X2. Possession already stops the plain case (W sealing X1's new keyset without holding it): notes/crypto.md, Holder actors at depth 0.

## The three leaks
Repros are osis-engine `rotation::tests_possession`, `#[ignore]`d on this issue, and all three fail today. In each one A holds k1 and then writes G under an epoch W opens.
- `removed_member_rotating_the_holder_actor_reads_nothing_spec_crypto_4`: W rotates X1 itself (k3 lists k1 and proves X2 at the old keyset W holds), then rotates G sealing X1 at k3. Every proof is judged and valid at A, because A cannot know W left X2. k3 descends from the knowing k1, so the spec's forgery limit ("until A is sealed at a keyset of M descending from a rotation of M that knows") claims this is safe, but it is not.
- `removed_member_sealing_a_made_up_keyset_reads_nothing_spec_crypto_4`: W rotates G proving X1 at a keyset nobody holds. The proof is not judged, and no held keyset lists the box. Model: core/test/tla/rotation `D0_rm_made` fails `NoLeakLimit`.
- `removed_member_backdating_a_rotation_reads_nothing_spec_crypto_4`: W stamps its rotation of G before k1 and proves X1 at k1 with a bad signature. Keysets are read as of the commit's key, so A judges no proof. Model: `D0_rm_back` fails `NoLeakLimit`.

## Why no node-local rule closes it
Candidate rule: an unjudged proof (its keyset had no valid body before the rotation) is a stale box of its epoch wherever the node holds a keyset of that holder. Model `AsOf`: `D0_rm_made_asof` and `D0_rm_back_asof` pass. It was built and dropped, for three reasons:
- **Only a partial fix.** It does nothing against the first leak, and W can always switch to that path. The rule also stops the made-up path only by making the honest case (below) cost a rotation every time. Principle: close leaks, don't shrink them.
- **A cannot tell attack from honest.** Take an honest co-writer C that rotated X1 again (k2, removing P) and then G, proving X1 at k2, while k2's carried body has not yet reached node N. N then holds what A holds in the made-up attack: k1, plus an epoch of G whose proof names an X1 keyset N has no body of. To be safe against W, N would rotate and seal X1 at k1, which P opens. The spec's Carried limit allows that, but it also sets off a cascade.
- **The cascade.** With the rule built, `removed_member_waits_spec_crypto_4` failed. An unaware W found X1's k1 "stale", because k1's proof names X2's new keyset, which W lacks (its removal is withheld). W rotated X1 at X2's old keyset, then rotated G, re-admitting itself. In G's Seal walk, a node holding X2's old keysets but never X2's new one would leave X1 out of G for good.

Treating an unheld keyset as an anchor with no candidate (leave X1 out, then re-seal) ends up sealing at k1 either way. Waiting for the body was rejected earlier: it strands rotations whose keyset is gone, and a made-up keyset never arrives.

## Options (Tess)
Study: issues/keys-depth0-rethink.md recommends a third way (demotions travel with the knowing keyset). It closes all three leaks at the limit as written and makes Possession redundant (models `D0_rm_*_travel*`).
1. **Widen the requirements limit** (spec/requirements.md Permissions, the holder-actor limit): a party removed from an actor below M, while A's writers still count it as a writer of M, may read A's new content until the removal's own new keys reach A's writers. Then state the forgery limit in spec/crypto.md §4 that way, and drop "descending from a rotation that knows".
2. **Carry keysets down the proof chain**: a rotation, grant or re-seal of A also carries the keyset commits that the carried keysets' proofs name, recursively, so A's writers hold X2's knowing keyset. The existing "a proof naming a stale keyset is a stale box" rule then makes X1's k3 stale at A, which closes the first leak once the removal's keyset arrives. This is a step past depth 0 (A holds keysets below its holder actors, but judges no departures). The made-up and backdated leaks would still need the candidate rule, with its costs. Needs modelling before building.
