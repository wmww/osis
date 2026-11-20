# grant's "secrets not held" names the wrong thing
> Summary: `grant` refusing with `Misuse("the secrets it derives from are not held")` (core/engine/src/rotation/mod.rs, after `ensure_rotated`) was met where the grantee's account chain was not held; the message names the thing's secrets, so a worker hunted the wrong cause.
> Priority: low
> Tags: engine

Check which `epochs` lookup fails when the grantee's chain is missing, and name it in the error (the grantee's account, not the thing).
