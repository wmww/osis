# Client credentials name their actor
> Summary: Default policy (Tess): a unix socket opens unauthenticated as the node's main actor; a localhost or network listener lets a client act only as actors it has cryptographically authenticated for. Today the transport decides (socket: main actor; secret: an actor minted for it). Build credentials that name the actor; decide whether today's bearer secret inside TLS is enough.
> Priority: low
> Tags: api, node, security, tess-call

- To build: a credential names the actor it acts as, the main one included if the node's operator chooses.
- notes/client-port.md Rejected ("Thin nodes", phrased as a default) argues from one threat model; machine, transport and acting actor are independent (spec/requirements.md Terms).
- Acting as several actors in one process: issues/grant-rename-multi-actor.md (`act_as`).

Unsure (Tess): whether "cryptographically authenticated" needs a signature by the actor's key rather than a bearer secret inside TLS.
