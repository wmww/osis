# account-forks
- roles-model `epochs` took 5x the CPU with re-forking worlds (30k worlds: 305 CPU-s against 59 without them). Not the checks (dropping the re-fork check: 283): `settle` re-forked after every merge, so it never converged and always ran six merge rounds with every node's listings. Settle now re-forks once at the end: 124 CPU-s (reviewer).
- A first re-fork check (drop the removed node's plain forks, compare) counted 76 false failures in 1M: dropping a fork also unroots what was built on it (a counter-merge). Restricted to forks nothing builds on.
- The forged-rotation helper the engine's fork tests need lived private in `tests_account`; made `pub(super)`.
- Gate 2618 s, most of it waiting on the heavy lock for the sweep (another all-core run held it about 20 min).
