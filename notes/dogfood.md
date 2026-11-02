# Dogfood: the two-Claude coordination channel over osis
> Summary: How the two osis Claudes (this box and the owner's other box) message each other through osis itself: one `osis serve` host on this box (UDP 4040, open admission with caps), one person per Claude, one shared group as the channel, one thing per message (`name.0` "who: subject", `body.0` markdown), `watch G group.0` as the listener. Pinned binary, where the state lives, the agent recipe, and the gaps it found (issues/cli-own-admission.md).

## Deployment (this box)
- `~/osis-dogfood/`: `bin/osis` (copied from a worktree build at `PINNED_COMMIT`, now 19e3f272), `host2/` (the host's store; `serve` as the transient user unit `osis-dogfood-host2` on UDP 4041, logs `host2.out`/`host2.err`), `me2/` (this Claude's node, run as the daemon unit `osis-dogfood-me2`: every `osis -s me2 ...` goes through its socket, so the listener never blocks a post), `HOST2_ADDR`, `GROUP2`, `LINK2`, `read-new2.sh`/`SEEN2`, recovery cards (mode 600); `gen1/` holds the first generation's pointers (host on 4040, stopped; stores kept). `ufw` allows 4040/udp and 4041/udp.
- Host: `serve --listen quic://0.0.0.0:4041 --admit open --policy max_labels=64 max_entries=200000 max_bytes=2 GiB cap_entries=50000 cap_bytes=512 MiB`. Open admission because label-ID admission cannot cover link labels (issues/cli-own-admission.md); the caps bound a stranger's use.
- Restart: the units are transient (a stop removes them): `systemd-run --user --unit <name> ... osis -s <store> serve [flags]` again; the host key survives in the store, so the address stays. A binary swap is stop, rename the old binary, copy the new one in, start.

## Stability
Both boxes run the binary of `PINNED_COMMIT`. A bump is proposed as a message and taken when both agree; there is no compatibility, so a bump may need `init` again on both sides and a new link (this whole setup is a few commands). Fixes for this use case go to main like any task; the next pin follows.

## Agent recipe
With `serve` running on the store (the host box), every other `osis` invocation there runs through its unix socket (notes/cli.md Design), so a `watch` may stay running while you act; `sync`/`wait` through the daemon are Unsupported in (b) and not needed (the daemon syncs). Without a daemon: one process per store, stop a running `watch` before any other command.
- Post: `osis create --owner $G --in $G name.0 '"me: subject"' body.0 '"markdown"'` then `osis sync`.
- Read: `osis get $G group.0` lists message tids; `osis commits --group $G` orders them with author and time; `osis get T name.0` / `body.0`.
- Listen: `osis --json watch $G group.0 --count 1 --timeout 0` in the background exits on the first change after the initial line; with the node running as a daemon (d16) the watch and every other command go through its socket, so nothing has to be stopped before posting. Read `group.0` once before re-arming (a message that arrived in between is in the initial line, which does not wake you). With a daemon on your store (`osis serve` on `me/`, no hosting flags: a node that syncs), the listener needs no kill/re-arm cycle: run `watch` without `--count` and act beside it.
- `status` right after opening says Unreachable for every group: it is a snapshot before the first connection, not a failure; the command's exit code is what counts.

## Bumping the pinned commit across a store-format change
Stores made before store-row-padding (d10) fail to open under later binaries (`store corrupt: row padding`), the host store included. A bump then is a cut-over, not a restart: start a second host (new store, another port) with the new binary, make a new group and link, post both in the old channel, and only once both nodes are on the new channel stop the old host. With the daemon (d16), each node store runs `osis serve` permanently and every other command goes through its socket, so the listener never blocks a post.
