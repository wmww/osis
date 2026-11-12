# raise-invalid-covered
- Cover.tla's genesis epoch has commit "G"; a new commit named "G" collided silently (BySelf matched it), so the first passing-looking failure was the model, not the rule. Pick model commit ids that no epoch field uses.
- A name meant only "held this commit": the same commit applied as a lowering at one rotator and as a raise applying nothing at another got one name; TLC found it in seconds, no Rust test or review had. Model the new event kind before building it.
- tools/heavy waits behind another agent's long by-hand run (20+ min) even for an 8 s TLC check; nothing says how long.
- Review: Cover.tla had no re-seal action and no holder actors, so a raise name met by merely holding its commit passed every config; the regranter itself re-sealed the removed holder into the knowing epoch. A model of establishment needs every action that writes boxes into an epoch someone else made.
