# account-forks
- roles-model `epochs`: `-- 1000000 epochs` takes about 15 min now (was 2-3): the per-prefix doubt and followed-line checks recompute `rooted` and lines, and the re-fork check judges once more. Worth caching per prefix if it is run often.
- A first re-fork check (drop the removed node's plain forks, compare) counted 76 false failures in 1M: dropping a fork also unroots what was built on it (a counter-merge). Restricted to forks nothing builds on.
- The forged-rotation helper the engine's fork tests need lived private in `tests_account`; made `pub(super)`.
