# Schemas that cannot be understood from the schema alone
> Summary: Where reading a schema file is not enough to know what the data means: chat retention set at run time, core protocol aspects that only the spec explains.
> Priority: normal
> Tags: tess-call, schema, chat

- **Chat retention**: messages are kept for good, but that comes from the chat's `required.0^` written at creation, not from the schema's declared retention.
- **Core protocol aspects** (schema/core.osis): `keys.0`, `secrets.0`, `label.0`, `addenda.0`, `seen.0`, `reach.0`, `host.0^`, `clients.0^`, `purge.0` are the protocol's own records; their docs can only point to the spec. Acceptable if apps are told to leave them alone; otherwise they could move out of the user-visible aspect space.
