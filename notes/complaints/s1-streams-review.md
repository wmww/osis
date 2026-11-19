# s1-streams-review
> Summary: Mishaps met reviewing S1 (streams by record).

- In the streams harness a body that opens as `Opening::Taken` (the `Table` default) leaves no store entry: `store.entry` reads none though the pull worked; check `knows` (what the source showed) instead.
- A late message's harm shows only for a member already at the stream: a member joining from the start is listed whatever the cursor says, so a late-reply probe on a first join passes with its rule disabled.
