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
Not a limit of 8 MiB of data: 4 GiB in one value is tested. A commit's header lists every chunk it adds, about 38 bytes each, and that list is capped at 8 MiB because a node holds it whole in memory. Chunks average about 80 KB, so the real limit is about 17 GB in one commit (estimated from those two numbers, not run), or about 220,000 chunks or parts. Past it the writer gets a plain refusal.
Tess: a commit should be able to upload GBs of data. Open: is about 17 GB enough? Otherwise raise the cap, which costs memory per header and lets a hostile header hold that much, or stream the lists, which is a build.
Recommendation: keep it now and write the number down; whole commits may change this list anyway.
