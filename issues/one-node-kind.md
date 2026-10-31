# One kind of node: blind per group, no separate server program
> Summary: owner direction: "server" gets no special meaning in osis (it is just osis running on a server, for whatever reason); a node is blind to some groups and not others, "blind node" is shorthand for a mostly blind node, not a technical term; any node can sync encrypted data it cannot read (structurally, not by default); no distinct server project: serving is part of the node, started from the CLI, configured through osis data. Terminology and code refactor. Design done (hosting is crate osis-host owned by the node, its own shredding store, config in a `host.0` aspect, `osis serve`); the sweep plan below does this with the roles rename and the AK format in one churn.
> Tags: design, spec, server, node, api

## Owner direction (round 13)
- **"Server" is not a role.** Many server applications want to process data, not just sync it. Within osis "server" means only that osis runs on a server machine. The spec and code today use "server" for "blind node used as a store" (spec/overview.md §terms, spec/sync.md throughout): rename the role (e.g. a node *hosting* a label, a label's *hosts*), keep "server" for deployment talk only.
- **Blindness is per group, not per node.** A node may read some groups and host others blind; "blind node" is informal shorthand for a node that is fully or mostly blind. Nothing in the code design should force a node to be one or the other. Example (not to build now): a sync service whose settings (accounts, rate limits) are osis data its admin writes; the service reads its configuration group and is blind to everything it hosts, in one osis instance.
- **Any node can host encrypted data it cannot read**, structurally, even if not by default (a normal node relaying or storing a friend's group).
- **No separate server project.** Hosting is part of the node; a CLI command starts a node that hosts (`osis serve` or similar); configuration may live in the osis database.

## Today
- `core/server` (~3k lines: blind store over osis-store backends, the hub, flow control and caps, replication, the driver) is a separate crate and binary with no actor keys; `core/node` syncs readable groups and serves them to member peers (`ServerConnection` over its own entries, notes/networking.md).
- spec/overview.md defines "Blind node: a node holding no read secret of a label it stores; 'server' is a blind node used as one", so the spec is already per label; the split is in code and wording.

## Design (answers to the design questions)
Terms: a node **hosts** a label (stores and serves it for anyone holding its role keys); the label's **hosts** are the addresses in its `/label` list. A node is **blind to** a label when it holds no read secret of it. "Server" is deployment talk only. On a connection the sides are the **client** (dialer) and the **serving side**.

### 1. Isolation
- The hosting code stays a crate, renamed `osis-host` (`core/host`, layer 6, library only). A crate boundary is the strongest check: the compiler enforces it, and `osis-node` depends on `osis-host`, never the reverse, so the host cannot reach the engine, keys or the sync state.
- tools/policy.py gets a `host_blind` check:
  - `core/host/Cargo.toml` normal deps ⊆ {osis-base, osis-crypto, osis-label, osis-proto, osis-store, osis-transport, tokio}; dev-deps ⊆ that plus proptest.
  - Every `osis_crypto::` and `osis_label::` path in `core/host/src` (outside `tests.rs` files) names only allowlisted items: crypto {`VerifyingKey`, `Signature`, `WRAP_LEN`, `OsRng`, `RngCore`, `CryptoRngCore`}; label {`blob_id`, `Prefix`, `MAX_PREFIX_LEN`, `verify_stamp`, `step::{parse_entry_box, entry_box_bytes}`, `Address`, `address_{to,from}_text`, `ClaimSet`, `Step`, `StepId`, the blind prefix parser}. No glob imports from either crate, and no `OpenKey`.
  - An allowlist fails closed, so a new decrypting call (`open*`, `unwrap*`, `decrypt_blob`, `kdf*`, any `*Secret` except transport's `StaticSecret`) fails policy.
- The node hands the host only public data: a `HostConfig` (listen URLs, admission, label ID set, replication peers, `HostPolicy`). In `core/node/src`, policy.py also allows only `osis_host::{driver, HostConfig, HostPolicy}`.
- Behaviour tests: the existing hygiene test (no tid, AK or author key in any stored byte) runs on a node that hosts, both for a label it reads and one it does not; a node-level test shows hosting works with every key record of the node absent.

### 2. Store
- The host keeps its own store: a second osis-store `Store` instance (`host.redb` plus its own root in the node's store directory). It holds no actor secrets, so even a shared type leaks nothing. Its rows are index tables and its blobs sit in the Store blob area.
- **Why not `Backend` directly, as today:** when a node hosts a label it can also read, the host's wraps and blobs survive a delete in freed pages. The same device holds the read secrets, so a later compromise yields deleted data, which breaks spec/requirements.md Deletion. On a `Store`, deletes shred (`Shred::Yes`), and the architecture §2 exception ("osis-server keeps rows on `Backend`") goes.
- Cost: hub inputs become store transactions, with one root write per shredding transaction. The step measures this against a host budget; owner call if it misses.
- **Why not one store with the node's data:** that would hand the host the store that holds actor secrets, and engine and hosting would contend on one lock.
- **Accepted cost:** no blob dedupe between the node's store and the host store. A label that is both read and hosted is stored twice.
- **Caps and accounting:** unchanged from today's `Policy`, renamed `HostPolicy`. Per label: `cap_entries`, `cap_bytes`, the ephemeral, presence and deposit budgets. Host-wide: `max_labels`, `max_entries`, `max_bytes`. Counted over the host store only (the node's own data is never charged). `host.0` may override caps per label ID.

### 3. Which groups a node hosts, configuration, finding hosts
- **Config is osis data:** core aspect `host.0` on the node's own thing: `{ listen: list<url>, admit: enum { own, open }, labels: set<label id>, replicate: list<address>, policy: optional knobs, per-label caps }`.
  - Any admin of the node thing (the person's devices) can configure a home node remotely.
  - It is never in the node card (the card's aspect selection excludes it).
  - Absent `host.0` means not hosting (the default).
- **Host key:** the host's static transport secret is a local record of the node (shredded when hosting stops). It is separate from the dialable key, so a `/label` host list never links to `/reach`.
- **Admission:**
  - `own` admits the labels of groups this node reads whose `/label` hosts list names this node's host address, plus `labels`. The node computes the ID set from `/label` data and hands the host only label IDs, no key state.
  - `open` admits any registration within the caps (today's server).
  - Either way, an unadmitted genesis Register gets code 12 (`admit_label`).
- **CLI:** `osis serve [--listen URL]... [--admit own|open] [--label ID]...` writes `host.0` when flags are given, then runs the node until SIGINT, printing the host address (`url#key`) first when hosting. It replaces both `daemon` and today's `serve`: one long-running command. Without `host.0` it runs a node that syncs and serves co-readers. A fresh box is `osis init`, then `osis serve --listen quic://0.0.0.0:7400 --admit open`.
- **Finding hosts:** unchanged mechanism, renamed.
  - `/label` `servers` becomes `hosts` (field id unchanged); the inbox blob's `servers` becomes `hosts`.
  - `osis::Config.servers` becomes `hosts`, `ServerAddr` becomes `HostAddr`, `add_server` becomes `add_host`.
  - CLI `server ls/add/rm` becomes `hosts ls/add/rm`, and `--server` becomes `--host`.
  - Links and cards carry host addresses. To host its own groups, an admin adds the node's host address to their `/label` lists (`hosts add`, `group sync --host`); `own` admission follows.

### 4. A node hosting a group it can also read: two stores, one protocol engine, chosen by listener
- **Host listener** (static host key, the address in `/label`): sessions go to the host's `Hub` over the host store, the same as for a label it cannot read.
- **Dialable and LAN listeners:** co-reader serving over the node's own entries (`sync/serve.rs`, as today).
- **The node's own copy** reaches its host as it reaches any host. The driver routes a dial to its own host address through an in-process link pair, with no socket. The sync engine sees an ordinary host: "placed" and convergence need no special case.
- **Not merged:**
  - Serving readable and blind entries from one store would make hosting depend on readability (key state), or make co-reader serving durable and authoritative.
  - Both already share osis-proto's serving engine; only the `LabelStore` differs.

### 5. Crate and module layout after the change
- **`osis-host`** (`core/host`, from `core/server`):
  - `store` (`HostStore` on osis-store `Store`, `HostPolicy`, totals, sweeps), `hub` (`Hub`), `replicate` (`Replicator`), `driver` (feature `driver`: tokio task over the host listeners).
  - Deleted: `bin/osis-server.rs`, `serve.rs` (`run`, `static_secret`), `config.rs` (config file format, `DEFAULT_DATA`).
- **`osis-proto`:** module `server` becomes `serving` (`ServingSession`, `ServingInput`, `ServingOutput`, `ServingConfig`). `client`, `store` (`LabelStore`, `MemoryLabelStore`) and the rest stay.
- **`osis-node`:**
  - Depends on `osis-host`, with no dev-dependency on it any more.
  - `SyncEngine` reads `host.0`, computes the `own` ID set and emits `Action::Host(HostConfig)` on change.
  - `sync/driver.rs` runs the host task, its listeners and the loopback. Its engine holder `Host`/`run_host` (osis: `OsisHost`) is renamed first (`Shared`/`run_shared`), freeing the word.
  - `sync/serve.rs` stays (co-readers).
- **`osis`:** `hosting()`, `set_hosting(HostConfig)`, `host_address()`; renames as in §3.
- **`osis-cli`:** no osis-host dependency (it goes through the API); `serve` as in §3; `daemon` deleted.
- **`osis-sim`:** depends on osis-host (sim-driven `Hub`s, as today, renamed).
- **`osis-transport`:** no structural change. The words "server key" and "server" become "listener key", "host" or "serving side"; the rustls and quinn API names stay.
- **osis-label:** `server_prefix` becomes `host_prefix`.
- The workspace drops `osis-server`. notes/architecture.md §1 rows, the layer DAG and §2 are rewritten. notes/sync.md "Implementation (osis-server)" becomes "Implementation (osis-host)".

## Owner: completeness (round 13)
"host" accepted as the term. The refactor must be complete: review passes explicitly hunt for remnants of the old split (types, module and crate names, config, CLI, test harnesses, spec and notes wording, comments, error texts, metrics, diagnostics). The end state should read as if it had been built unified from the start; no adapters, aliases or "formerly server" notes. Same standard for the roles/members rename.

## Sweep plan (this issue, issues/rename-roles-members.md, issues/aspect-key-format.md)

### Order and gating
- **Start condition:** issues/group-access-follows-membership.md has merged. It adds `tied` to the `/members` value and touches the same words.
- **Freeze window, steps 1-5:** the five mechanical renames run back to back. No other branch touching core is in flight, since every one of them would conflict.
- **After the window:** steps 6-9 are ordinary feature steps and may interleave with other work.
- **Why words before behaviour:** the new code (step 8) is written once, in the final vocabulary, with `host.0` born in the final AK format.
- **Per step:**
  - One opus worker, then a fresh opus reviewer. The reviewer runs `tools/gate.sh` after `git rebase main`, plus `python3 tools/spec_map.py` (its anchors quote spec text, and every rename step updates them), plus the remnant hunt below.
  - Renames are scripted (sed over `git ls-files`, then compile-driven fixes). The reviewer reads the diff of the script itself, not 5k hunks.
  - Wire changes regenerate vectors. Data from earlier builds may fail to load (CLAUDE.md, no compat).
- **Hunting conventions:**
  - `G` = `git grep -nIE`, run over `-- . ':!docs'` (docs/ is exempt).
  - A residue list (each match left, with why) goes in the reviewer's report.
  - Each hunt also lists file names (`git ls-files | grep -iE <word>`), and the identifier census `G -o '\b[A-Za-z_]*<Word>[A-Za-z_]*\b' | sort | uniq -c` must contain no old-sense name.

### Steps

1. **Free the word, move the crate (a; M, about 1.2k occurrences).**
   - The node driver's `Host`/`run_host` and osis `OsisHost` become `Shared`/`run_shared`/`OsisShared`.
   - `core/server` becomes `core/host` (`osis-host`), with the dependency inverted (osis-node depends on osis-host). `BackendStore` becomes `HostStore`, `Policy` becomes `HostPolicy`, and proto `server` becomes `serving` (`Serving*`).
   - The `osis-server` binary is deleted; `osis serve` calls `osis_host::serve::run` until step 8.
   - Hunt:
     - `G 'osis[-_]server|core/server|BackendStore|\b(Host|run_host|OsisHost)\b'` returns nothing.
     - `G 'Server(Connection|Input|Output|Config)\b|proto::server\b|mod server\b' -- core cli ':!core/transport'` returns nothing.
     - Read: root Cargo.toml, notes/architecture.md §1-§2 and §4 (`driver` feature sentence), notes/build.md (feature unification), crate docs of host, proto and node.
2. **Host words everywhere (a; L, scripted, about 5k occurrences).**
   - Spec, notes, issues, code, API, CLI, tests, sim, TLA, fuzz, kit/app:
     - server becomes host or serving side; `servers` in `/label` and the inbox struct becomes `hosts`;
     - `ServerAddr` becomes `HostAddr`, `Config.hosts`, `add_host`; CLI `hosts ls/add/rm` and `--host`;
     - test names (`hostile_server`, `evil_server`, `*_server_*`); `issues/server-hub-stall.md` becomes `host-hub-stall.md`.
   - spec/overview.md defines host and "blind to a label"; "blind node" stays only as informal shorthand.
   - Hunt:
     - `G -i '\bservers?\b'` and `G -i 'server'`. The allowed residue is only: rustls/quinn API names in core/transport (`ServerConfig`, `ServerCertVerifier*`, `server_name`, `with_server_*`), iroh-relay's `server` feature (Cargo.toml, architecture §5), and deployment prose ("an official host on our servers").
     - `G -i 'blind (node|server)'`: only the informal uses.
     - `G '"servers"|--server\b|server (ls|add|rm)'` returns nothing: CLI flags and JSON keys.
     - `G -A8 'impl_error!' | grep -i server` returns nothing: error texts.
     - Diagnostic kinds and sim notes: `G -i 'server' -- core/test/sim core/engine/src/events`.
     - Read: spec/overview.md, spec/requirements.md (Untrusted nodes), spec/sync.md (whole), spec/wire.md §10-§11, spec/data-model.md §9-§10, notes/sync.md, notes/networking.md, notes/api.md, notes/cli.md, notes/testing.md, notes/testing-map.md, tools/spec_map.py, core/test/tla, core/test/fuzz targets, app/ and kit/ call sites.
3. **Roles words in spec, notes and issues (b; M, about 1.2k occurrences, no code).**
   - Add one terminology section in spec/permissions.md §1, mirrored in spec/data-model.md:
     - **Rights:** role, role grant (edge), holder (of a role on X), role commit (was membership commit), role-class aspect (was membership-class), role timeline (was membership timeline), co-reader open (was member open, proof 3).
     - **Organization:** member, membership, member of a group (`/group`).
     - **CRDT:** set "member" becomes element.
   - The `/members` literal stays until step 5.
   - Hunt: `G -w '[Mm]ember(s|ship|ships)?|MEMBER(S|SHIP)?' -- spec notes issues`. Every match must be the organization sense; read each one.
4. **Roles words in code (b; L, about 4.5k occurrences).**
   - Identifier renames: `MemberKeys` becomes `HolderKeys`, `is_membership_class` becomes `is_role_class`, `MembershipCommit` becomes `RoleCommit`, `remove_member` and the like become `*_holder`; `Proof::Member`/`OpenKey::Member` become `CoReader`, with domain `"osis v1 co-reader open"` and vectors regenerated.
   - `core/test/membership-model` becomes `roles-model`; TLA modules and the osis API and CLI words follow (`roster` lines `holder X`).
   - Hunt:
     - `G -w '[Mm]ember(s|ship)?'` plus the identifier census for `[Mm]ember` with `remember*` excluded: only placement-sense names remain.
     - `G 'member open|Proof::Member|member_open|served_members'` returns nothing.
     - `git ls-files | grep -i member` returns nothing.
     - Read: osis API docs (`lib.rs`, `share.rs`), CLI help and JSON keys, tools/spec_map.py, tools/policy.py and spec_map MODELS paths, test names.
5. **AK grammar and spelling (c; L: about 300 lines in osis-base, about 200 in the DSL and codegen, about 1.6k literals in 128 files, 42 schema declarations, vectors).**
   - `Ak` parses the grammar: segments over `[a-z_][a-z0-9_]*` joined by `:`, an optional leading `:<tid>` segment, `.N` always written, and markers `^` then `~` or `*`. Accessors: `segments`, `version`, `tid`, `admin`, `lifetime`, `successor_of`.
   - `namespace()` and `is_core` by leading slash go away. The DSL writes `aspect contact:names.0: ...`; core keys become `name.0`, `keys.0`, `roles.0` (from `/members`), and so on.
   - Markers only parse here: schema validation requires a key's markers to match its schema flags until step 7. A build-time test asserts every generated constant parses.
   - Hunt:
     - `G '"/[a-z]'` and `G '^aspect /' -- '*.osis'`: only non-AK paths remain (file paths, URLs).
     - `G 'namespace|is_core\b'` and `G '/members'` return nothing.
     - Read: CLI AK argument syntax and notes/cli.md examples, `osis://` URI forms, schema/README.md, notes/std.md, notes/data-model.md (namespaces), app/ and kit/ keys.
6. **No schema ID or revision on the wire (c; M).**
   - The header's schema table and per-aspect schema index go (spec/data-model.md §10, spec/commits.md, spec/wire.md), as do `SchemaId`, `CORE_SCHEMA_ID`/`REVISION` and the `schema 0x...;` line.
   - Schema files keep a human `version`. The node picks a local schema for an AK from the schemas it has, never from the wire. Vectors are regenerated.
   - Hunt: `G 'SchemaId|schema_id|CORE_SCHEMA|schema table|schema index'` returns nothing; `G -w revision` matches only the human version. Read the commit header layout in spec/wire.md against osis-commit's encoder.
7. **Markers carry meaning (c; M).**
   - `~` (ephemeral) and `*` (signal) come from the key; the `ephemeral` and `signal` schema flags leave the DSL and the `flag` enum.
   - `^` admin-only is judged by validity: a write of a `^` aspect needs admin on the thing. This replaces notes/permissions.md "Admin-only aspects (accepted)" and adds a spec/permissions.md rule.
   - Presence stays a schema flag until issues/eph-unify.md decides.
   - Hunt: `G 'Flag::(Ephemeral|Signal)|\b(ephemeral|signal)\b' -- core/schema schema` (DSL docs, flag lists); read spec/data-model.md §2 and §10 and notes/versioning.md.
8. **Hosting in the node (a; L, about 2k lines added, 700 removed).**
   - `host.0` core aspect; `Action::Host`; the node driver runs the host task, host secret and loopback; `own`/`open` admission; the osis API `hosting`/`set_hosting`/`host_address`.
   - `osis serve` as in §3, with `daemon` and osis-host's `serve.rs`/`config.rs` deleted; the policy.py `host_blind` check; tests as in §1 plus own-mode admission, a node hosting a group it reads (a remote client is served from the host store, and the node's own copy is placed through the loopback), and the CLI `serve`.
   - Sim: a world node may host (the sim steps its `Hub`).
   - Hunt:
     - `G 'static_secret|DEFAULT_DATA|osis-server-data|server\.(redb|key)|--config|\bdaemon\b|Daemon'` returns nothing.
     - `G 'Hub::new' -- ':!core/host'` matches only the node driver and sim.
     - No second way to start hosting, and no "dedicated" or "standalone" hosting mode in code or notes.
     - Policy check: the reviewer adds `use osis_crypto::kdf;` to a host file once and confirms policy.py fails.
     - Read: notes/cli.md, notes/api.md (Sync configuration), notes/node.md module table, notes/networking.md (decisions 3, 5 and 6, now about hosts), spec/data-model.md §9 (`host.0` row).
9. **Host store on osis-store `Store` (a; L, about 1.7k lines of `store.rs` rewritten).**
   - Shredded deletes; a throughput measurement against a new host budget in notes/testing.md; the architecture §2 `Backend` exception removed.
   - It may run beside other work once step 8 has merged.
   - Hunt:
     - `G '\bBackend\b|WriteBatch|RedbBackend|MemoryBackend' -- core/host core/node core/osis` matches only store construction.
     - notes/architecture.md §2, notes/local-store.md and notes/sync.md (What a blind node learns) state the shredding.
     - The hygiene and forensic tests run over the host store.

### Close-out
- After step 9, one fresh opus reviewer runs every hunt above once more on main. It also reads spec/overview.md and spec/sync.md top to bottom as a newcomer would: does anything read as if a separate server program, member-as-rights or slash keys ever existed?
- Then this issue and the other two are deleted, after their lasting decisions move to notes: notes/sync.md (hosting), notes/permissions.md (terms), notes/data-model.md (AK grammar).
