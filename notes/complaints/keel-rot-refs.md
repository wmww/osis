# keel-rot-refs
- The brief's five `rotation_holds_large` failures (keys.0 reference rows) were already fixed on main by 54c2fda4e: the failing run was on a branch built before it landed. Replaying one seed on origin/main before starting would have shown it in two minutes; briefs should give the commit a failure was seen at.
- Writing a background command's log into a scratch directory not yet made fails silently inside `tools/heavy` (exit 1, no run): mkdir first.
