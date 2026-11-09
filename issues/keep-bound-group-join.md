# A thing joining a listened group is not armed for keep bounds
> Summary: `T_KEPT` timers for listed value parts are armed for a listener's things (a group's members) at registration and per listened aspect when its state changes. A thing that joins a listened group later has its aspects armed only on their next state change, so a replaced kept part of it leaving at its bound before then is not told to the group's commit listener (a page read shows it).
> Priority: low
> Tags: engine, api

Fix shape: arm the joining member's aspects (`listing::arm_keep_bounds`) when a membership change puts it in a listened group, as registration does.
