# Tracked reads at a connected node
> Summary: On a tracking handle, `groups_of`, `role_on`, `holders`, `profile_of`, and `stream`/`byte_len` fail `Unsupported` when the thing is at a connected node, since the client port has no subscription filter for them. Values, listings, a thing's aspects and grants track over the port.
> Priority: low
> Tags: core, port

No client-port filter says when those answers change. A wire filter per read (or one generic "this read row's answer" filter, the server re-reading on the same internal listeners as a local tracking handle) would close it. Until then the failure is visible, never a stale answer (notes/api.md Tracked reads).
