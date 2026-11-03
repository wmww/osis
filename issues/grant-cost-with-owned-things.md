# A grant slows with the things its author owns
> Summary: Probing many grants from one sender, each `grant` took about 0.4 s at 320 things owned (dev build, loaded), up to 1.8 s in another probe; not profiled, likely on main too.
> Tags: engine, scale

Seen in the inbox-budget probes (`grants` in core/node/tests/it/inbox_retry.rs, 320 fresh group things by one person). Look at it if members-cost's measures (notes/testing.md) do not cover it.
