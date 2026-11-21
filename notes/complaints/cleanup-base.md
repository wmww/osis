# cleanup-base
> Summary: deprecated_probe's "unused outside" list misses a method used on a type the probe doesn't own a name match for; a truncated grep (`| head`) hid a caller.

- `deprecated_probe --dead osis-base` listed `Stamped::reader` dead but not `StampedSet::reader`/`Stamps::reader`; I widened the removal by grep and cut it at `| head`, missing `p.pairs.reader()` in engine. The build caught it. Grep callers without `head` before removing a `pub` item.
- notes/coordination.md's Cleanup brief section did not print with a `sed -n '/Cleanup brief/,/^###\? /p'` range (heading form differs); read it with Read instead.
