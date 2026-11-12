# churn-843
- The listed seed (807204137843) had stopped failing on main after net step 3h2 changed the message flow, so the KNOWN line pointed at nothing. Finding out cost a `tools/bin-at` build of the old commit. A wide range of seeds around it showed the class that is still live (two divergences, plus a loop and a debug assert).
- The churn failure dump listed the commits each node held but not what they wrote, so it took a patch to see which commit was the expired leftover. `lane_dump` now prints `aspect_dump` for both aspects.
