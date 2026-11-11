# lifetimes-3d
- Tests that called `judge_lifetimes` by hand after `net.run()` broke once node sync judges on its own: the node had already released. A test wanting "nobody judged yet" must keep the right holders offline (`set_online`) or not run the net in between.
- An osis test (`references::rows_follow_the_values`) listed a retainer that did not reference its thing; with the trigger the thing is released at once. Tests writing `retainers^.0` need a referencing retainer.
- Host-entry checks (`entries(l)`) see only the entries the asking node knows: checking "at the host" from one node's view gave a false failure when the other node placed or deleted the entry.
