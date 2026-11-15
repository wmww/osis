# A node's dial list entry is written only at listen
> Summary: `publish_reach` runs only after a listen and at `rotate_peer_address`, so a node whose own `dial^.0` entry another node dropped (`dial::drop_departed`, e.g. it saw the node's fresh entry before its re-pairing) stays undialable by contacts until its next listen.
> Priority: low
> Tags: sync, engine

- Possible only if a node of P can apply a re-paired node's profile write before the role commit re-adding it to D; unverified whether judgement parks that write.
- Fix if real: the node follows its own entry (an `Effects` over the dial list and its `reach.0`) and writes it back whenever it is missing while it is on D.
