# An ending that falls invalidates rotations made while it stood
> Summary: Possession substitutes an ended actor t's frozen holders for t only while t reads ended (`Ending::of`). A purge ending can fall (its request's author removed upstream). A rotation of a dependent x made while the ending stood boxes t's frozen holders, not t; its author, an admin of x through t, proved no possession of t. Once the ending falls every node re-judges it with t as holder actor in place, the author holds its role on x only through t, and the rotation turns invalid: content written under its epoch since loses its key.
> Priority: normal
> Tags: keys, engine, retention

- Expiry endings never fall; only purge endings with a concurrent upstream removal of the purger.
- Not modelled (Depth0 `End(t)` is permanent) and no test.
- Directions: (a) possession judges t's frozen holders in t's place for a commit stamped after the ending's request whether or not the ending still stands (the commit was written on a standing ending); (b) the stated limit, as any rotation premised on an authority that a concurrent removal later invalidates.
