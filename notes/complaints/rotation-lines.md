# rotation-lines
- A world test rotating an account three times passes the default delivery cap (about 650 deliveries per rotation: each goes under every sync ID the account acts in); the storm message reads like a loop until counted.
- No test hook rotated an account from `tests/it`; added `Engine::rotate_account`.
- An old-epoch write could not serve as the fresh reader's check: a rotation's thing list never reaches S's other readers (issues/rotation-thing-lists-under-s.md), so the test verifies the later rotations (signed at old epochs) instead.
- (review) Each world node holds two connections per peer (one dialed, one accepted) and streams every new entry on both, so one account rotation in a 3-node introduced world costs about 1 000 deliveries; a partition adds about 1 000 more per `advance` past PASS_WAIT (dial ticks).
