# What a stranger's open fires leave behind
> Summary: Open fires let anyone holding a thing's public key record write: the fires stored are bounded only by the sender's rate times the inbox's history setting.
> Priority: normal
> Tags: engine, sync, security

- **Rate × `INBOX_LIFETIME`.** A promoted fire leaves the deposit budget, so fires stored on an inbox are bounded by the sender's rate times its history setting only (notes/inbox.md accepts no rate limit). State it as a storage bound (issues/reference-graph.md Storage) or bound it.
