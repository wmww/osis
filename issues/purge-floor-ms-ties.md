# Purge floors at ms granularity
> Summary: `purge_before` floors and the stamps they are compared with are wall ms, so two writes or settings in one ms are ambiguous: a body written in the same ms as the setting ending a purge, before it, escapes the floor, and the join's skip cannot tell which of two settings in one ms ended which (over-purge at a node lacking one). Floors as full `ts` would remove both.
> Priority: low
> Tags: engine, security

spec/commits.md §5 One way compares `wall_ms(ts) < F`, and F is a setting's `wall_ms(ts)`.
- Leak: under purge on replace, a write stamped in the same ms as the keep that ends it (and before it) is not under F, so once replaced it shows under the keep. Same for the join's floor at a concurrent keep's stamp.
- Over-purge: a purging setting and the next one in one ms give a floor equal to the purging one's own stamp, so the skip ("a held floor past its own stamp") does not apply; a node holding the purging setting and a later one but not the one between dates its end by the later one and purges more (held-model `a_carried_join_makes_older_settings_add_nothing` leaves worlds with two settings in one stamp out for this).

Fix: make `purge_before` a full `ts` (HLC) and compare the oldest dead write's `ts`; `Kept::floored` and its callers (`written_of`, `live_until`, `forever`, `kept_whenever_replaced`) take `ts` instead of wall ms. Exact `ts` ties across nodes remain, as for every stamp order.
