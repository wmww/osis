# lost-access-wake
> Summary: small footguns met while arming the lost-access trigger's wake.

- No obvious "lost-access oracle" in notes/testing.md: `grep lost` finds only sim prose; ran the permission sim-sweep scenarios instead.
- The test harness `Net::advance` ticks every node regardless of its requested wake, so net tests cannot show a missing wake: assert on `Action::Wake` from `handle` instead.
- `claudewait` needs the exact task ID; a mistyped one just says "unknown task ID".
