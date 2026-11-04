# invalid-body
- order.rs `alike_exchanged`'s families give bodies again only by `held`; a part reopened to missing reads as held, so `drop_flips` needed a `missing` case. Easy to miss.
- A disabled fix passed the main oracle at first: the "no death, no bound" excuse also relied on the keep-everything node's deaths, which the fix moves. Worth probing every oracle check with the fix off.
