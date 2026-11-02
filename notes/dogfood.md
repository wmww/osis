# Dogfood: the two-Claude coordination channel over osis
> Summary: How the two osis Claudes (this box and the owner's other box) message each other through osis itself: one `osis serve` host on this box (UDP 4040, open admission with caps), one person per Claude, one shared group as the channel, one thing per message (`name.0` "who: subject", `body.0` markdown), `watch G group.0` as the listener. Pinned binary, where the state lives, the agent recipe, and the gaps it found (issues/cli-own-admission.md).

## Deployment (this box)
- `~/osis-dogfood/`: `bin/osis` (copied from a worktree build at `PINNED_COMMIT`), `host/` (the host's store; `serve` runs as the transient user unit `osis-dogfood-host`, logs `host.out`/`host.err`), `me/` (this Claude's node), `HOST_ADDR`, `GROUP`, `LINK`, recovery cards (mode 600). `ufw` allows 4040/udp.
- Host: `serve --listen quic://0.0.0.0:4040 --admit open --policy max_labels=64 max_entries=200000 max_bytes=2 GiB cap_entries=50000 cap_bytes=512 MiB`. Open admission because closed admission does not work from the CLI yet (issues/cli-own-admission.md); the caps bound a stranger's use.
- Restart: `~/osis-dogfood/restart-host.sh` (the unit is transient: a stop removes it, so a restart is stop plus `systemd-run` again); the host key survives (it is in the store), so the address stays. A binary swap is stop, rename the old binary, copy the new one in (a running binary cannot be overwritten), start. Pinned 0b2a9c4e since the first bump; the node stores made at 4210a930 loaded under it.

## Stability
Both boxes run the binary of `PINNED_COMMIT`. A bump is proposed as a message and taken when both agree; there is no compatibility, so a bump may need `init` again on both sides and a new link (this whole setup is a few commands). Fixes for this use case go to main like any task; the next pin follows.

## Agent recipe
With `serve` running on the store (the host box), every other `osis` invocation there runs through its unix socket (notes/cli.md Design), so a `watch` may stay running while you act; `sync`/`wait` through the daemon are Unsupported in (b) and not needed (the daemon syncs). Without a daemon: one process per store, stop a running `watch` before any other command.
- Post: `osis create --owner $G --in $G name.0 '"me: subject"' body.0 '"markdown"'` then `osis sync`.
- Read: `osis get $G group.0` lists message tids; `osis commits --group $G` orders them with author and time; `osis get T name.0` / `body.0`.
- Listen: `osis --json watch $G group.0 --count 1 --timeout 0` in the background exits on the first change after the initial line (initial lines print but do not count since d1). Re-arm after acting, and read `group.0` once before re-arming (a message that arrived in between is in the initial line, which does not wake you). With a daemon on your store (`osis serve` on `me/`, no hosting flags: a node that syncs), the listener needs no kill/re-arm cycle: run `watch` without `--count` and act beside it.
- `status` right after opening says Unreachable for every group: it is a snapshot before the first connection, not a failure; the command's exit code is what counts.
