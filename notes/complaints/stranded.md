# stranded
- An inbox blob taken through `held`'s `Effects` is taken again whenever anything its take read moves; an engine take that writes durable state (a stranded notice's ask) must be idempotent by content, or it loops through passes. Not obvious from `take_inbox`'s doc.
- Status's per-S `Effects` closures must read the stamped `sources` inside the closure; reading it outside records nothing and the key never comes due again (cost a debugging round).
- (review) Engine local-row prefixes were scattered over a dozen files with no registry, so two branches picked `ra/` unseen; policy's `row_prefixes` now refuses a colliding or literal row key.
- (review) No cheap shape refuses an asked re-seal while its holder stays current (an ended grant is finalized first), so the "stays asked" path is untested.
