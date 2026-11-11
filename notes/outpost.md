# Outpost
> Summary: Design under discussion with Tess, nothing built: outpost, a program that runs boxes (the machine it is on, later others) and exposes each as osis data. Each box is one security context; the box writes all its data, others only fire requests at its console; each request taken at most once becomes a run the box owns. Terms, data model, request lifecycle, retention, v1 scope, open questions.

Part of moving agent orchestration onto osis; useful for any remote control of machines. Usage may be clunky: the aim is to expose the needed functionality, with tooling (app views, a control CLI) later.

## Principles
- **One writer per thing.** Outpost writes everything a box shows. Others write nothing of it; they fire requests at the box's console. No shared editing, no conflicts, nothing a requester can alter after the fact.
- **A box is a security context.** Everyone who may command a box sees all of it. Finer separation means more boxes (a VM per party, someday), never permissions inside one: with arbitrary commands, hiding anything is obscurity.
- **Requests are signals, results are things.** A request is a fire with a verified sender, on the one thing others write; what comes of it is a run, outpost's own thing.
- **One mechanism for every request kind.** New features add request kinds and result types, never a new path.

## Terms
- **outpost**: the program (binary `osis-outpost`). One running outpost runs one or more boxes under one osis identity: it can act in every box it runs, so separate identities would add nothing; splitting trust means separate outposts.
- **box**: a place commands run, one security context. The **backend** says how commands reach it; v1 has only `local` (the machine outpost runs on). Other backends (a remote machine over SSH, ...) are future work and unspecified; only the boundary is kept: runs, output, console and take-once are the same on every backend.
- **console**: the one thing of a box others write: they fire requests at it.
- **request**: a fire on a console. Kinds: `exec` (a command line, run by bash), `input` (bytes to a run's stdin), `cancel` (end a run). First-class tools (repos, worktrees, agents) come later as more kinds.
- **run**: what outpost makes of a request it takes: the request, its sender, state and output. Named by its request's commit ID.
- **specs** (fixed facts: hostname, OS, CPUs, RAM, disk) and **vitals** (live: load, free RAM and disk) of a box.
- **queued**: a request with no run yet. **Taken**: it has one.

## Data model
Per box, one group (the box's security context) whose readers are everyone who may see the box; outpost is its admin. In it:
- **The box thing**: `specs` (durable, rewritten when they change) and `vitals` (ephemeral, an expiring write outpost renews, `osis::KeepAlive`). Vitals present = the box is up; when outpost dies they lapse.
- **The console**: a thing on which the box's commanders hold write and nothing else. Its one aspect is the request signal: durable (`~`, not `+`), so a request fired while the box is offline waits, and the record of what was asked is kept as long as the console's `retention^.0` says.
- **Runs**: one thing per taken request, written by outpost only. State as a value; output as a durable signal on the run, one fire per chunk (each write small however long the run; chunks kept or expired per the run's `retention^.0`, read as the signal's history). The box thing lists no runs (a growing list is the scaling problem); runs are found through the group.

Sketch (DSL shapes, not final):
```
type request = enum {
    exec 0 (struct { command 0: string, cwd 1: option<string> }),
    input 1 (struct { run 0: request_id, bytes 1: bytes }),
    cancel 2 (struct { run 0: request_id }),
};
signal outpost:request~0: request;            // on the console; kept per its retention^.0 entry

aspect outpost:specs.0: struct { hostname 0: string, os 1: string, cpus 2: u32, ram 3: u64, disk 4: u64 };
ephemeral aspect outpost:vitals+.0: struct { load 0: ..., ram_free 1: u64, disk_free 2: u64 };

type run_state = enum {
    running 0,
    exited 1 (i32),            // exit code
    killed 2 (option<string>), // cancelled, or the signal that ended it
    refused 3 (string),        // not allowed, expired, bad request
    lost 4,                    // outpost restarted while it ran
};
aspect outpost:run.0: struct { request 0: request_id, sender 1: tid, kind 2: request, state 3: run_state };
signal outpost:output~0: struct { stream 0: enum { stdout 0, stderr 1 }, bytes 1: bytes };
```
`input` and `cancel` name the `exec` request, not the run, so they can be fired before it is taken.

## Request lifecycle
- **Take once.** Outpost takes a request by writing its run (state `running`, or `refused`) in one commit before starting anything. The runs are the taken set: a request is taken iff a run names it. After a restart a run still `running` with no process becomes `lost`; a request is never run twice.
- **Staleness is expiry.** Every request expires (the schema gives a default; the sender may set its own). Outpost takes only unexpired requests; osis drops expired fires anyway. So a request delivered late does not run late, the sender picks how late is too late, and outpost needs no limit of its own.
- **Edits and removals act only while queued.** A sender's edit (an honored `replaces`) or removal of a queued request changes what outpost takes; outpost reads the newest version at take time and ignores versions of a request it has already taken. Ending a running command is a `cancel`.
- **Every request is answered.** Not allowed (outpost's own rules per sender, if any), expired at take, or malformed: a run in state `refused` with the reason, so a sender always sees an outcome.
- **Order.** Outpost takes a sender's requests in their order; `input` for a run waits until its `exec` is taken, and is dropped with the run's end.

## Retention
Runs, output chunks and console requests each need a default: kept for a duration then expired, unless kept on purpose. The taken set needs nothing extra: a run outlives its request's expiry, so a late duplicate of the same request is either still named by its run or already expired.

## v1
One outpost, local backend, one box. Requests `exec`, `input`, `cancel`. Specs and vitals. A control CLI to fire requests and follow runs (maybe just `osis` commands). No first-class tools, no other backends, no UI.

## Open
- How outpost reaches osis: a client of the local `osis serve` daemon over its socket (notes/cli.md) with its own actor (notes/client-port.md), or its own store.
- Who may fire what: write on the console is the only grant. Does outpost apply per-sender rules on top (some senders `exec`, others later kinds only), or is that more boxes too?
- Removing a queued request: purge by its sender (needs the request's purgeable-by to allow it) or an edit to a withdrawn form.
- Output: chunk size and flush interval; whether live output should also go ephemeral for low-latency tailing, with durable chunks for the record.
- Retention defaults for runs, output and requests.
- Model the lifecycle (take once, edits only while queued, expiry, restart) before building.
