# The app has no state for a node removed from its account
> Summary: A node removed from its account (or lowered below write) acts for none (`Account::of` none), so kit's `home()` fails `Invalid`: the app refuses to start on such a store, and a removal arriving while it runs fails every render that reads home. Decide what the user sees (make a new account as a fresh store does, or a "removed" screen offering that) and build it.
> Priority: low
> Tags: app, kit

`kit::store::open` makes an account only for a new store; `render/start.rs` checks `home()` and reports a failure otherwise. Nothing in the app watches for the account going away.
