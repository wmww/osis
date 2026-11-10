# left-out-holder
- The issue's sim shape (per-chat persona) misled: the real-API World test never reached the window, because a removed account drops the team's secrets before acting, unless its removal applied without the rotation and it rotated before the lost-access drop. An engine-level test with an edges-only delivery was the only quick way to reach it.
- Depth0 had no notion of "a node stops following an actor it left" (Syncs is static), so the stranding could not show until `Follow` was added; `RD` also counted a device removed from a holder actor as leaking content it reads as the thing's admin.
- Review: the World tests (`shared_with_team`) passed with the fix disabled and took 8-33 s for two; removed. The engine test is the guard.
