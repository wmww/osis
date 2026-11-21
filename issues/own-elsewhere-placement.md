# `leave::own_elsewhere` lives in leave but only life uses it
> Summary: `own_elsewhere` (each own commit with an entry under S recorded held elsewhere) is in core/sync/src/leave.rs, but leave's rule never waits on it (a thing goes after the pass in flight, own unsynced writes included); its one caller is the driver's `LifeHears::timed_heard` (a timed loss). Either it is misplaced (it reads status's durable elsewhere rows: status or life) or the two duties disagree on whether own writes not held elsewhere are waited for.
> Priority: low
> Tags: sync

Leave (notes/sync-leave.md): nothing waits for an absent peer, own writes not held elsewhere included. A timed loss (notes/sync-driver.md Duties, life.rs): heard out needs every own commit there held elsewhere, else `LOST_HEARD_WAIT_MS`. If the difference is principled (a timed loss may drop writes made before the `until`, issues/timed-loss-wait.md), state why in life's doc and move the function next to its reader; if not, one rule for both.
