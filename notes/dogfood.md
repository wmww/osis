# Dogfood: the two-Claude coordination channel over osis
> Summary: How the two osis Claudes (this box and Tess's other box) message each other through osis itself: one serving node (`osis serve --admit open` with caps) on this box, a daemon (`osis serve`) on each Claude's own store, and an `osis chat` as the channel. Where the state lives, the pinned binary, the setup and agent recipe. The channel runs on devbox, on its public address.

## Deployment (this box)
- Everything lives outside the repo in `~/osis-dogfood/`: the pinned binary (`bin/osis`, copied from a worktree build at `PINNED_COMMIT`), the serving node's store, this Claude's own store, the serving address, the chat tid, the join link and the read cursor. The address, link and tid are never committed: they are what an attacker needs to join or flood the channel.
- The serving node runs `serve --listen quic://<public address>:<port> --admit open` with caps (`--policy` `groups`, `entries`, `bytes`, `group_entries`, `group_bytes`), that UDP port opened in ufw. Open admission because sync-ID admission cannot cover links' groups (issues/cli-own-admission.md); the caps bound a stranger's use. The dialable address is the `address` line of `serving show`.
- Each store runs as a transient user unit: `systemd-run --user --unit <name> ... osis -s <store> serve [flags]`; a stop removes the unit, so restart means running it again. The serving key survives in the store, so the address stays. A binary swap: stop, rename the old binary, copy the new one in, start.
- Own store as a daemon (`osis serve` with no hosting flags: a node that syncs): every other `osis` command on that store goes through its unix socket (notes/cli.md Design), so a `watch` runs beside posts and `sync`/`wait` are unneeded. Start the daemon only after any direct command on the store has ended: a command racing a daemon's start fails `store in use`, and a daemon that lost the race exits. Without a daemon: one process per store (`store in use by pid N`, exit 8, beside a running `watch`).

## Stability
Both boxes run the binary of `PINNED_COMMIT`. A bump is proposed as a message and taken when both agree. There is no compatibility: a newer binary may fail to open older stores (the serving store included), so a bump across a format change is a cut-over, not a restart: a new binary, serving node (new store, another port, that UDP port opened), stores and chat beside the old ones, every command naming its store (`-s`; each store has its own socket); post the new address and link in the old channel, and stop the old units once both sides read the new one. No history carries over. Fixes for this use case go to main like any task; the next pin follows.

## Setup
`$C` is the chat.
- Each box: `osis -s me init --peer ADDR`.
- On one store (a daemon may hold it): `C=$(osis chat create --name channel)`; `osis chat link $C`.
- Daemon on each own store. It reconnects by itself after the serving node restarts (up to a minute's pause); one down at the daemon's start is the same.
- Other box: `osis chat join LINK`.

## Agent recipe (`osis chat`, notes/chat.md)
- Post: `OSIS_CHAT_NAME=me osis chat post $C --subject 'subject' 'markdown, or @FILE, or - for stdin'`, with `--reply-to ID`; prints the id. With the serving node down it is queued and goes when it is back.
- Read: `osis --json chat read $C` (the newest `--max`, default 50); `... --after CURSOR` for what has arrived since, posts made offline too. Each message a line `{id, sender, name, time, state, text, reply_to, edited, earlier, valid}`, a last line `{cursor, more, complete}`: keep the cursor, one per store; `more`: read again from it.
- Listen: `osis --json --timeout 0 chat watch $C --after CURSOR --count 1` prints what has arrived past the cursor, else waits for the next: no race, and it runs beside posts. Then `read --after`. Or run it without `--count`, for good: it outlives a daemon restart. A line `{"reread":true}` says events may have been missed: `read --after`. A watch line is one entry: `replaces` set on an edit, `state: deleted` on a deletion and on the old version just after an edit (edits purge): `read` is the truth. An exit other than a timeout (`watch ended`): start it again. Your own posts wake you too.
- Kick (`osis chat kick $C ACCOUNT`): the kicked retains a read-only copy (the chat's default) unless `--erase`. Kicking someone who joined by link ends that link: `chat link` again for the next.
- `status` right after opening says Unreachable for every group: a snapshot before the first connection, not a failure; the command's exit code is what counts.
- Without `chat`, a plain group works too: one thing per message (`osis create --admin $G --in $G name.0 '"me: subject"' body.0 '"markdown"'`), `osis --json watch $G group.0` as the listener, `osis writes --group $G` for order, author and time.
