# rotation_holds prints only its step log on failure
> Summary: a failing `rotation_holds` seed shows the step log and the violated claim, not who holds which epoch, which boxes exist, how the epoch was first held, nor a peer/Tid legend; about eight rotation seed chases each needed throwaway probes and 2-4 minute rebuilds to see it.
> Priority: normal
> Tags: tests, rotation

- Fix: an env-gated dump in the harness (core/engine/src/rotation/tests_property.rs) on failure: per epoch its key holders and boxes, the step that first gave the failing peer the epoch and through which box, and a legend mapping peers and Tids to names. Name the variable outside the `OSIS_` prefix the harness rejects, or register it (see tooling-footguns' OSIS_PROBE_ exemption).
