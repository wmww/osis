# rotation-lines
- A world test rotating an account three times passes the default delivery cap (about 650 deliveries per rotation: each goes under every sync ID the account acts in); the storm message reads like a loop until counted.
- No test hook rotated an account from `tests/it`; added `Engine::rotate_account`.
- An old-epoch write could not serve as the fresh reader's check: a rotation's thing list never reaches S's other readers (issues/rotation-thing-lists-under-s.md), so the test verifies the later rotations (signed at old epochs) instead.
