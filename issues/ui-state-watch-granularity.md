# UI state in osis: every node-state write re-reads the whole tree
> Summary: node state lives in a map aspect on the window (`ui:week.0: map<path, int>` etc.); a write to one entry fires the thing watch on the window, so the shell re-renders every node (its models compare equal and are then dropped). A watch on a map entry or a "changed paths" report would let one node re-read. Unmeasured; the cost per navigation or composer keystroke scales with what the tree reads.
> Priority: low
> Tags: core-ask, app

Each keystroke in a composer eventually commits through its session and fires this too. Ask: a thing watch that reports which aspect and map entry changed, usable to re-render only that node.
