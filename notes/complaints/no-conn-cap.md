# no-conn-cap
> Summary: footguns met while removing the connection count limit.

- `Up::Opened` and `Down::Keep` existed only to feed the cap's eviction; nothing in their docs said so, so removing the cap needed a whole-tree grep to see they had no other reader.
