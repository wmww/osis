# A fork held only by nodes that may not rotate its role is never re-sealed
> Summary: Re-seals come only from nodes that may rotate the role; a current epoch whose secret only non-rotators hold (its rotator boxed only itself, then was demoted) stays current, and content written under it stays unreadable to every other holder.
> Tags: permissions, keys, engine

`rotation::tests::forks_with_departures_settle_large` (osis-engine lib, tier 2), seed 39 (before its re-seal check was narrowed to epochs some node that may rotate holds): writer peer 1 rotates read leaving out every other holder (the test's random leave-out; honest code leaves a holder out only when its keyset is unknown or its newest epoch does not cover), concurrently with peer 0's read rotation; peer 1 is then demoted to read. Its fork (n 4) is current at every node and the newest by nonce; only peer 1 holds it, and a reader writes no boxes (spec/permissions.md §3 re-seal: "a node that may rotate a role"), so the other holders never get it and what peer 1 wrote under it while a writer stays unreadable to them. The next read rotation removes peer 1's box there and supersedes it, without its secret.

Rare (needs every other node that may rotate the role left out of the fork), so only noted. A fix would let any current holder of the role re-seal an epoch only it holds, which widens who writes `secrets.0`.
