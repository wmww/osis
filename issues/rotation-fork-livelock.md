# Concurrent rotators fork a role forever
> Summary: Three nodes that may rotate T's sync role each hold one of two current sync epochs and lack the other; an epoch whose secret a node lacks counts as uncovered, and a rotation that boxes a rotator is due, so each rotates again and the forks never close (OSIS_FULL differential seed 81: n climbs past 66, a new step per rotation, never quiet).
> Priority: normal
> Tags: engine, keys

## What happens
- Seed 81's last step revokes node 2's account from T (a sync holder; `Revoke(1, 0, Holder::Node(2))`). After it, nodes 0, 1 and 3 each write `keys.0` + `secrets.0` rotations of T's sync role (then a step, `sync.0`), with no other commit, until the storm cap.
- Every one is `rotation_due` (Encrypt) through `unread && boxes_rotator`: T has two current sync epochs of the same n, the node holds one and lacks the other; the lacked one is uncovered by the departure (an epoch whose secret it lacks covers nothing here), and the rotation's recipients include a holder that may rotate (holder actor H, admin on T). Each node's new epoch forks again beside the others' and the loop goes on.
- `boxes_rotator` assumes a rotator boxed reads the new epoch. Here the box goes to holder actor H at admin, and the other rotators still lack the epoch: unstudied whether they lack H's keyset it was sealed to (H's keys rotate in the same storm) or never take the box.

## To find out
- Which rotator fails to read which epoch, and why (the probe that found it: `rotation_due`'s reasons and each node's `commit_in`, per node root).
- The rule that ends a fork of epochs nobody covers: one rotation per departure, whoever makes it, judged the same at every node (spec/crypto.md §4 Encrypting under).
