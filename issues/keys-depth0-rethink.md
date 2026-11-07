# Rethink "a group never looks inside its member groups" (depth 0)
> Summary: Tess doesn't recall choosing depth 0 and leaves it to us: remove it or replace it with whatever rule makes most sense. Today one rule bends it (a node holding a member group's keys and knowing someone left won't hand out that group's old key or write under a parent key passing it on; notes/crypto.md, Blocked through holder actors), and it still leaks when a second admin of the parent cannot read the member group (issues/blocked-walk-stops-at-readers.md, models `D0_readers_g2`, `D0_above_g2`; candidate "mark" needs a wire field). Fold into the keys redesign (issues/design-coherence.md B) where natural; state the principle first.
> Tags: keys, security
> Priority: normal
