# Most retention roots have no test that fails without them
> Summary: tools/mutate.py on `retention::needed::rooted` against the engine, sync and osis default tests: only held (in the closure or leaving it) and a held key actor (`Core::key_actors`, by the making cost test alone) are caught. A retained copy (`ix.kept`, `forget::copy_of`), the node's own key actor, a bearer, the K of a followed link, a held key actor named holder on a thing, and an own self-removal's wait each turn off with every test green.
> Priority: normal
> Tags: engine, retention, tests

Each needs a test where it alone keeps a thing at a pass end, or it goes. Likely overlaps (check first, delete what never decides):
- The node itself: its node root's creation commit is signed by it (`Need::Signed` from a closure thing).
- A followed link's K and "a held key actor named holder on it": once K's roster is held, L (held in `key_actors` while followed) is named holder on K, so the first decides only before the roster arrives or after L's grant ends.
- A bearer: decides only where K is outside the node closure.
- A self-removal's wait and a retained copy: the facade and rotation tests hold the thing in the closure throughout, so `Root::Held` decides; a test must release the thing (or lose the path) while the wait or the copy stands, then end a pass.
