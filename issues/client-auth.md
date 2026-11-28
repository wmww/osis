# Client credentials name what they act as
> Summary: Default policy (Tess): a unix socket opens unauthenticated as the node itself; a localhost or network listener lets a client act only as things it has cryptographically authenticated for. Today the transport decides (socket: node itself; secret: a client's thing minted for it). Build credentials that name what the client acts as.
> Priority: low
> Tags: api, osis, security, tess-call

**Question for Tess**: does "cryptographically authenticated" accept today's bearer secret inside TLS, or must the client sign with the actor's key?

- To build: a credential names the thing it acts as, the main one included if the node's operator chooses.
- notes/client-port.md Rejected ("Thin nodes", phrased as a default) argues from one threat model; machine, transport and the account acted as are independent (spec/requirements.md Concepts, Client).
- Acting as several things in one process: issues/act-as-several.md (`act_as`).
