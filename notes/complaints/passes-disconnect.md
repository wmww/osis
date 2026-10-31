# passes-disconnect
- Net harness: `set_online(n, false)` drops every event to n, and calling `net.sync(n).handle(..)` directly while offline throws away its `Dial` actions, so the node never redials after `set_online(n, true)` (looks like a sync bug). To cut one server off, use `net.blocked.insert((n, s))` + `net.drop_link(n, s)` instead.
