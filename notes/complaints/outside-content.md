# outside-content
> Summary: Footguns met on outside-content.

- The issue predated the fix that closed it (a release keeping a commit whose part may come back, a late part's record never learned); its reproducer passed on main at once. Checking an old issue against later commits first would have saved the hunt.
- `send_carried` sends only parts under sync IDs the receiver syncs: a thing minted under an account the receiving unit cannot read never enters, which reads like the bug. The mint admin has to be readable through the strong's unit.
