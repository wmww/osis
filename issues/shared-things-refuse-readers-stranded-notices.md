# Kit and chat things refuse their readers' stranded notices
> Summary: kit, the app and chat enable no external signal on what they mint, so a stranded notice (`stranded@~0`) fired by a reader or sync-only holder of a document or chat is invalid; such a holder, stranded with no writer connected, waits for a writer to connect or to re-seal it on its own trigger.
> Priority: low
> Tags: kit, chat, tess-call

- Tess: an account's inbox enables both external signals, nothing else by default; core has no default (spec/sync-inbox.md §1). That decision was put as "takes no grant from outside", and a shared thing needs no grant signal (grants are made on it, to holders whose inboxes take them). Stranded notices are a separate matter: they go on the stranded thing itself, from its own holders, to its writers (spec/permissions.md §4 Stranded).
- Where it bites: a reader whose keyset changed (its account removed a node) holds boxes at the old keyset; the notice carries its new holder keys, the way a writer not following the holder learns them (spec/crypto.md §4, Reported). Without it, re-seal waits for a Stranded message on a connection to a writer.
- To decide: kit and chat enable `stranded@~0` alone on what they mint (one setting entry each, no grant signal), or the refusal stands.
