# A removed admin can still purge what was written before its removal
> Summary: `purge_allowed` judges a request by its author's right at the request's own `ts` and ignores whether the request's commit is valid. A removed admin signs a request stamped before its removal, naming any delta stamped earlier; the demoter's frontier leaves that commit's delta invalid, but every node drops the named body, deletes it at hosts, and shows the purge as rightful. Same for a removed writer's own messages. Before this was only a loss of a body; lasting tombstones also show it for good.
> Tags: security, engine, permissions

Repro: admins a, x and writer w; w writes c; x signs p naming c, unseen; a demotes x with a frontier missing p; everyone gets p. At every node `body_not_dropped(c)` is false and `purged_on` names p, though x has no role and p's own delta is invalid (x's clock or a held-back commit: the same thing as a backdated forgery).

Bound since purge-tombstone: a request names only deltas stamped before it, so what comes after the removal is safe.

Fix to weigh: a request counts only while its commit's delta on the named thing is valid (a request carries a delta). That makes a purge fall on a validity flip, which issues/purge-before-demotion.md says has no path back today (the body is gone, the value-less list stays), so the two want one design: re-judge, take the delta out of the value-less list, fetch the body again from a holder. `known_purged` then has a validity input to wait on. An honest admin's unseen purge racing its own demotion would fall too, which is what frontiers do to its other writes.
