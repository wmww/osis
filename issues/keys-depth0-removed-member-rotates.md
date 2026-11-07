# A removed member can seal a group at a keyset nobody holds
> Summary: Unverified (found by reading). A writer W of G through holder actors, removed from one where its removal is unknown, may box the holder actor at a keyset nobody holds (or one it forged); such a box is never stale (no keyset lists it), so G stays on W's epoch until G rotates for another reason, past the limit in spec/requirements.md Permissions. Possession (built) stops the plain case.
> Priority: normal
> Tags: security, keys, engine

## Shape
G <- X1 <- X2 <- {W (write), R (read)}; B, admin of X1 and X2, does not sync G. B removes W from X2 and rotates X2 and X1. Before W learns its removal it rotates G. Possession (notes/crypto.md, Holder actors at depth 0; spec/crypto.md §4 Authority) makes W box X1 signed by a keyset's possession key, so W cannot seal X1's new keyset, whose secret it lacks: an unprompted rotation seals X1's old keyset and is stale at G's admin once it holds X1's new one. Test: osis-node `revokes::nested_departure_removed_writer_waits_spec_crypto_4`; engine `rotation::tests_possession`; model core/test/tla/rotation/Depth0.tla `D0_rm_*`.

## Left
W is a writer of X1 (it writes G through it), so where its removal is unknown it can write a keyset of X1 itself and seal and sign at it: "a keyset of M the removed party forged where the removal has not arrived", within the stated limit only while M's next knowing rotation has not reached G's writers. Worse: W may name a keyset nobody holds, which needs no write at all. A box naming an unknown keyset is not judged and not stale (both by design: a co-writer may have sealed to a keyset not received yet, and readers who cannot see M's keysets must not refuse honest rotations), and no keyset ever lists it, so G's writers keep writing under W's epoch after X1's knowing rotation reaches them.

To check: a test where W, removed from X2 unknown at G, rotates G boxing X1 at a made-up keyset; then X1 rotates knowing; then G's admin writes; assert W cannot open it (`openable`). Options if it leaks: a box to M naming a keyset that M's current knowing keyset does not list, once that keyset is held, counts as stale (risk: a co-writer's honest box to a keyset still in flight goes stale and costs a rotation); or widen the requirements limit (Tess's decision).
