# rotation-seeds
> Summary: footguns met root-causing the rotation property's seed failures.

- An own commit refused as invalid (`apply_local`) surfaces as a bare `Permission { tid }` with no hint which rule (Authority, role, overreach) refused it; finding it took a temporary backtrace at every `Error::Permission` site plus a per-part dump of `delta_valid`/`possessed`/`shown`. A debug-only helper naming the failing rule would save that.
- The property's failing history lists steps but not who holds which epoch or box; the second issue needed a temporary per-peer dump of current/held epochs and missing boxes at the failing check.
