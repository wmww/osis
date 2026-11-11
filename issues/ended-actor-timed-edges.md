# A timed edge on an ended actor is never finalized
> Summary: Keys read no clock: an edge past its `until` stays a holder for keys until its finalize, a write on its thing. Nobody writes an ended actor t, so an edge on t past its `until` at the ending, or expiring after it, stays one of t's frozen holders for keys for good: what t held a role on keeps boxing it (spec/crypto.md §4, Holder actors, Ended, Limit), though its authority through t lapsed at the `until`.
> Priority: low
> Tags: keys, engine

- Options: (a) the stated limit (today); (b) frozen holders read `until` at the ending point (agreed: the ending's time), so an edge expired by then is none, and one expiring later stays (a smaller leak, still one); (c) frozen holders read `until` by the clock, the departure attributed to nothing (the dependent rotates once each node's clock passes it): a clock read in keys, against "keys read no clock".
- Tess: no preference; (a), the stated limit, stands. Revisit only if timed grants on things that end turn out common.
