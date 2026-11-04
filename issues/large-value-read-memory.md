# A read of a large value decodes it whole, at up to 56 B per byte
> Summary: `osis_label::read_value` decodes up to `MAX_READ` (1 GiB) of a linked value whole: `osis_base::decode` is linear (56 B per byte at worst) so a writer's hostile value can cost a reader about 56 GB, once it reads that link.
> Tags: security, label, engine

`read_large` and `read_large_max` read a link's canonical bytes and decode them. An 8 MiB blob is now bounded at about 450 MB, but a linked value is many blobs: `MAX_READ` is 1 << 30 and `osis`'s read limit passes through `read_link`. Only someone who can write to the thing can link such a value, and a reader pays only on reading it.

Possible fix, not designed: a byte limit for a whole read that follows from what 56 B per byte may cost (the local policy `MAX_READ` is what is arbitrary here), streams for what is above it.
