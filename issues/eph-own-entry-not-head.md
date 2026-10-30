# An own ephemeral entry refused 9 is never sent again
> Summary: the ephemeral lane treats code 9 (stamp not under the head's write key) on an own entry as final (`eph_status` only logs it), so an entry uploaded before the node holds the new head's write secret (it opened by claim at a step from a rotation it has not read yet, or built the entry offline under the old keys) never reaches that server; its other readers there never get it.
> Tags: sync, ephemeral

Repro: `ephemeral::gained_announced_again_after_refused_sync_spec_sync_5` with, at the end, `net.advance(60_000)` and `notes(c, w)`: b's note written offline never reaches c; b logs "ephemeral upload refused: code 9". Same without the held Opened (b reconnects after the rotation).

Where: core/node/src/sync/ephemeral.rs `eph_status` (code 9 falls to the diag arm), `eph_upload` (stamps own entries under the connection's `keys.write`, kept stale when it has none for the head).

Fix direction: on 9 for an own entry, drop it from the upload records and send it again once the connection's head keys give a write key (the durable path re-uploads at its next pass); a non-own entry refused 9 was stamped by someone else under an older key and cannot be fixed here.
