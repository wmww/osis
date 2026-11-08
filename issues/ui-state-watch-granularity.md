# UI state in osis: every node-state write re-reads the whole tree
> Summary: node state lives in a map aspect on the window (`ui:week.0: map<path, int>` etc.); a write to one entry fires the thing watch on the window, so the shell re-renders every node (its models compare equal and are then dropped). A watch on a map entry or a "changed paths" report would let one node re-read. Unmeasured; the cost per navigation or composer keystroke scales with what the tree reads.
> Priority: low
> Tags: core-ask, app

Design: notes/listener-design.md (proposal): a path listener `db.at(t, k).path(p).on_change` at any depth, the address `get` already has, no changed-paths report and no map-only watch; kit re-renders per node through it (build steps 2 and 5).

Each keystroke in a composer eventually commits through its session and fires this too. Ask: a thing watch that reports which aspect and map entry changed, usable to re-render only that node.

Note from tess: if you decide to do this, be sure to think through the implications on the overall API philosophy, and let whatever changes to that ripple through the rest of the design. if you add a second, unrelated listener function that specifically works for a toplevel map and nothing else I will hit you with a stick /s
