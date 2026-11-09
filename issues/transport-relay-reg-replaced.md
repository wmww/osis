# A replaced relay registration still looks registered
> Summary: A newer REGISTER for the same key overwrites the relay's entry but leaves the old registration stream open, so the old registrant keeps publishing a relay it can no longer be dialed through.
> Priority: low
> Tags: transport

Found by reading, not run. core/transport/src/p2p.rs: REGISTER inserts over the old `regs` entry and never ends the old stream, so `Registration::once` on the old side keeps `held` open and `observed` set. Triggers when two listeners share a dialable secret: a node restarted within the old connection's 60 s idle, or a copied config. Fix: the relay finishes the loser's stream, so its `run` loop re-registers and it learns.
