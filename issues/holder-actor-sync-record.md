# A group holding sync alone has no sync record of its own
> Summary: The sync record (spec/sync.md §3) is an account's (`kept^.0` on its D). A group actor G holding sync alone on T gets T's boxes in G's inbox; each account reading G must accept T itself, and one that starts reading G after `INBOX_LIFETIME` gets no box of T until T's next rotation or a re-seal.
> Priority: low
> Tags: sync, engine

- Today: the offer sits in G's inbox (a boxes payload to G's keyset), held by every node reading G while unexpired; each reading account's accept keeps T's sync ID in its own record and its nodes record the secret once their path bears it. Nothing durable carries T's sync ID or current secret to a later reader of G.
- Option: a record on G itself (`kept^.0` on G, written by G's admins on their accept, read by every reader of G), the same rule one level up: G's readers trust G's admins as an account's nodes trust the account. Not specified until a use needs a group holding sync alone (none does yet).
