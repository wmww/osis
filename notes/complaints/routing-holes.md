# routing-holes
> Summary: Mishaps met on the routing-holes branch.

- A new arm of a seeded differential can pass without ever running: the split arm never ran while routed in all 3 seeds, and only a disable-the-fix run showed it. Check per step, and assert the case was reached.
