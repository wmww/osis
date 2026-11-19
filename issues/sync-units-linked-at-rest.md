# A privacy pass over what a node keeping data unread learns
> Summary: Tess: a node keeping units unread will need to know whom it works for, at least by account, for billing and abuse, and the earlier requirement that it learn nothing of the kind was not thought through; she accepts that such a node can tell which of its units share a writer. A pass for maximum privacy here may come someday. Not now.
> Priority: low
> Tags: sync, security, spec

What such a node learns (spec/requirements.md, Data a node cannot read): which opaque sync units each item is in and how they overlap; that units share a writer, since one blob is wrapped under each sync ID that carries it, so a writer's evidence copies and its public profile, carried under every unit its owner writes in, are the same blobs under each; and whatever account it keeps data for. Hiding the evidence route (a fresh encryption per unit) while the profile route stays buys nothing, so neither is hidden.

For the pass, if it comes: what a node really needs to know to bill and to refuse abuse; whether a writer's units can be kept apart for an identity whose point is privacy (issues/actors-one-mechanism.md, identities managed through another).
