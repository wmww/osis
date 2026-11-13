# A doubted open head whose walk ran out ignores the peer's later heads
> Summary: an open head doubted (`Open { doubted }`, sync/open.rs `doubt`) whose Behind walk found no earlier step with a credential stays doubted; a later stream head that is neither its child nor recorded calls `doubt` again, which is a no-op at the same head, so that connection never learns the peer's head (L stays open, registers nothing there) until a Lost, a close or a reconnect.
> Priority: low
> Tags: sync

- Reached only when every recorded step before the doubted head that holds a credential is refused 14 (this node holds no credential of a step on the peer's path, e.g. no genesis key and a fork above every step it can name).
- Simple fix candidate: in `new_head`, while `doubting`, ask a Behind item on the head again (bounded by the peer's head moves; nothing is registered while doubted, so no Register storm). Needs a test that exhausts the walk, then moves the peer.
