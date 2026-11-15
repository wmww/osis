# A remote group admin can make a local thing carried
> Summary: an admin of any synced group this node holds can add a local thing to it by ID (`group.0` needs only write on the group); the thing is then carried and this node's later writes on it go out under that group's sync IDs: sealed to the thing's readers, but count, size and timing reach the group's members.
> Priority: normal
> Tags: sync, security, tess-call

spec/sync-set.md §1 states it as a Limit. The requirement's words ("in no synced group … stays local") still hold, but this is a metadata leak kept as a limit (Close leaks). Alternative: count as carrying only a group add authored by a party holding a role on the thing, so a stranger's add carries nothing. Needs Tess's call on whether "local" must mean "only this node decides".
