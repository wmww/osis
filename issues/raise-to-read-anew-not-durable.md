# A raise to read is fetched anew only within the session
> Summary: S raised from kept unread to read is pulled anew from each source (`Store::set_holdings`, the `anew` feed), so entries it refused unread come again; the raise is not durable, so a restart between the raise and streams' reset finds S read with no raise and the refused entries never come.
> Priority: low
> Tags: sync, store

- The window is one driver step (the raise and `pull_anew` run in the same settle unless the step fails or the node stops there).
- A fix would mark the raise durably (as `N/` marks a dropped copy) and clear it in `pull_anew`'s transaction; `N/` itself does not fit (it makes S take nothing).
