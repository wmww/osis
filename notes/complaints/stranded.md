# stranded
- An inbox blob taken through `held`'s `Effects` is taken again whenever anything its take read moves; an engine take that writes durable state (a stranded notice's ask) must be idempotent by content, or it loops through passes. Not obvious from `take_inbox`'s doc.
- Status's per-S `Effects` closures must read the stamped `sources` inside the closure; reading it outside records nothing and the key never comes due again (cost a debugging round).
