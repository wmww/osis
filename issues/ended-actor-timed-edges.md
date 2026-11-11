# A timed edge on an ended actor is never finalized
> Summary: Keys read no clock: an edge past its `until` stays a holder for keys until its finalize, a write on its thing. Nobody writes an ended actor t, so an edge on t past its `until` at the ending, or expiring after it, stays one of t's frozen holders for keys for good: what t held a role on keeps boxing it (spec/crypto.md §4, Holder actors, Ended, Limit), though its authority through t lapsed at the `until`.
> Priority: low
> Tags: keys, engine, tess-call

- Options: (a) the stated limit (today); (b) frozen holders read `until` at the ending point (agreed: the ending's time), so an edge expired by then is none, and one expiring later stays (a smaller leak, still one); (c) frozen holders read `until` by the clock, the departure attributed to nothing (the dependent rotates once each node's clock passes it): a clock read in keys, against "keys read no clock".
- Question for Tess: is a timed grant on a thing that then ends common enough to want (c)?
