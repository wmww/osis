# s1-record-review
> Summary: Mishaps and slow spots met reviewing the S1 record-keyed restructuring.

- `World::step_or_wake` in a loop never returns false while any node dials a partitioned peer (its horizon moves with the clock): bound such a loop by world time, or it hangs the test.
- A test observing what a peer was served by its store after `run()` is defeated when the peer drops S's entries on learning it no longer holds S: check after each delivery instead.
