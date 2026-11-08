# Schemas that cannot be understood from the schema alone
> Summary: Where reading a schema file is not enough to know what the data means: chat messages hidden in a CBOR blob whose list is the register's history, chat retention set at run time, core protocol aspects that only the spec explains, and the `ro`/`indexed` flags that mean nothing.
> Priority: normal
> Tags: tess-call, schema, chat

- **Chat messages** (schema/chat.osis): `chat:msgs.0` is a `blob` holding a CBOR map the DSL cannot type, because a map `overwrite` leaves per-entry state that grows each write on a long aspect (an engine cost worked around in the app). The message list is the register's write history, which the schema cannot say either. Fix candidates: a type that merges as one register while typed (an "atomic" wrapper), and a way to declare an aspect as a log of writes.
- **Chat retention**: messages are kept for good, but that comes from the chat's `required.0^` written at creation, not from the schema's declared retention.
- **Core protocol aspects** (schema/core.osis): `keys.0`, `secrets.0`, `label.0`, `addenda.0`, `seen.0`, `reach.0`, `host.0^`, `clients.0^`, `purge.0` are the protocol's own records; their docs can only point to the spec. Acceptable if apps are told to leave them alone; otherwise they could move out of the user-visible aspect space.
- **Flags `ro` and `indexed`** (schema/meta.osis): declared and parsed, read by nothing, defined nowhere. Define them or drop them.
