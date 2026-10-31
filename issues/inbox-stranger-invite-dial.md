# A stranger's invite still makes devices dial its servers
> Summary: inbox hints are vetted (one per blob, only a thing the commit boxes the actor on, gone with the blob), but a box that opens proves only that the sender knows the actor's KEM key: a stranger with the deposit seed can keep up to the inbox's deposit budget of invites to its own things live, and every device dials the servers they name (IP and online-time leak), and stored grant copies refill at budget per `INBOX_LIFETIME` / 2.
> Tags: security, sync, node, api

The grant cannot be verified before its label is opened (the granter's chain is under that label), so vetting before dialing is not possible in general. Options: an app-level accept step for invites from authors with no known chain (dial only after accept), or dialing such labels only through a relay. Needs an owner call on whether unsolicited invites may cost a dial.


Owner decision (round 13): an accept step. Leaking an IP address should take a user click. Invites from a sender with no connection to the recipient (no role in anything the recipient holds a role in, not in its contacts) are not fetched or dialed until the user accepts (like message requests); invites from connected senders go through as now. Needs a small API (list pending requests, accept, decline) and a clear rule for "connected" in the spec.
