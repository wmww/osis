# A snapshot's carried bound is a counter hull: mixed sessions rebuild at expiry
> Summary: An expiry strips in place only where no held snapshot's carried bound (per source, the least and greatest counter it holds valued) meets its writes. A session writing lasting values on an aspect both before and after one of its expiring writes puts that write inside an honest snapshot's hull, so its expiry rebuilds the aspect: O(aspect) instead of O(delta).
> Priority: low
> Tags: engine, performance

Reachable honestly: a chat whose disappearing setting is turned off and on again within one session, or lasting and expiring writes interleaved on one aspect. Correct either way (the rebuild finds no carrier). A tighter bound (ranges per source) grows with how often a session alternates; the hull keeps the index O(sources). notes/expiry-creation-design.md Expiry in place.
