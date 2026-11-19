# s1-take-review
- World tests of a change while a peer is away pass with the in-place judgement removed: the first reconnect after first contact is a renamed take that judges every member. Mutation-check such tests with the peer away and back once first.
- A judgement mutation that returns early without unfollowing leaves the memo key due, so a later step judges the member anyway and the mutation looks harmless; mutate to the old behaviour (unfollow), not to a bare return.
- Box load was over 20 on 16 cores during the review: single-test wall times were 3 to 5 times the quiet ones.
