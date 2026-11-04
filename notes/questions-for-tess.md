# Questions for Tess
> Summary: Open requirement and edge-case decisions, written for Tess to answer when she has time; each with a recommendation. Coordinators append; remove an entry once answered (record the answer in spec or notes).

Background for all of these: notes/core-triage.md §2.


## 7. Recovering a group from a vandal admin vs keeping an honest key change
Background: if an admin goes rogue and changes a group's key so nobody else can read new content ("lockout"), another admin can recover by removing them and throwing away the rogue key change. The device doing that can't always tell a rogue key change from an honest one it simply didn't get a copy of (it was offline, or left out by mistake).
Today: recovery throws away any key change by the removed admin that this device can't open. That always recovers, but it can also throw away an honest one; content written under it then stays unreadable to people who join later.
Tried fix (branch `repudiation`, not merged): keep the key change if any remaining member might have a copy. Review found a vandal can then fake a copy "for the owner" that nobody can check, which blocks recovery for good.
Options: keep today's rule (recovery always works; a rare honest key change can be lost for later joiners), or the fix plus "only the owner's own devices can recover from a vandal who targeted the owner" (more rules, still a hole for other admins).
Recommendation: keep today's rule. Recovery always working matters more, and the loss needs an admin to be both stranded and doing a recovery at the same time.

## 8. A limit on how big one change can be
Requirement: a change may touch any number of things, with no size limit. In practice one change's list of parts has always been capped at 8 MiB, about 250,000 parts, because a node holds that list whole in memory. So far the cap was unwritten and only the writer checked it.
Proposal: write the number into the spec and the requirement. A bigger change would have to be split by the app, or we would build streaming for these lists later.
Recommendation: accept. Changes that big are rare, and the writer gets a plain refusal.
