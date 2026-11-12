# order-role-commit
- held-model hand tests: new things numbered 20/21 silently collide with `gen::ACCOUNT`/`LINK_K`; the commits then just vanish from `Outcome::valid` ("no entry found for key"), no error. Pick ids from 40 up.
