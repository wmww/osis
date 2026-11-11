# no-conn-cap
> Summary: footguns met while removing the connection count limit.

- `Up::Opened` and `Down::Keep` existed only to feed the cap's eviction; nothing in their docs said so, so removing the cap needed a whole-tree grep to see they had no other reader.
- Spec requirement "Peer input never causes ... unbounded allocation" (spec/requirements.md) now has a stated exception (spec/sync.md §10 Served connections); worth a line in requirements if Tess wants it explicit.
