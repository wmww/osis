//! The command tree (notes/cli.md Command table; notes/cli.md). Help text stays terse.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "osis", version, about = "osis from the command line: read, write, watch, share and sync things", disable_help_subcommand = true)]
pub struct Cli {
    #[command(flatten)]
    pub g: Global,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Args, Debug, Clone, Default)]
pub struct Global {
    /// Store directory [env OSIS_STORE; default $XDG_DATA_HOME/osis/default]
    #[arg(short, long, global = true, env = "OSIS_STORE", value_name = "DIR")]
    pub store: Option<PathBuf>,
    /// Machine output: one JSON document per command (JSON lines when streaming)
    #[arg(long, global = true)]
    pub json: bool,
    /// Numbered keys and ms timestamps even with a schema
    #[arg(long, global = true)]
    pub raw: bool,
    /// Use this schema too (repeatable)
    #[arg(long = "schema", global = true, value_name = "FILE")]
    pub schemas: Vec<PathBuf>,
    /// Bound for anything that waits (`30s`, `5m`; 0 = forever)
    #[arg(long, global = true, value_name = "DUR")]
    pub timeout: Option<String>,
    /// Only errors
    #[arg(short, long, global = true)]
    pub quiet: bool,
    /// Diagnostics on stderr while a command that syncs runs (as `diag --follow`)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Materialization bound in bytes
    #[arg(long, global = true, value_name = "BYTES")]
    pub limit: Option<usize>,
    /// Run the command at this node as a thin client (URL#KEY; needs --client-secret, no store)
    #[arg(long, global = true, value_name = "ADDR", requires = "client_secret")]
    pub node: Option<String>,
    /// The file holding the thin client's secret (64 hex digits, as `clients add` printed it)
    #[arg(long = "client-secret", global = true, value_name = "FILE", requires = "node")]
    pub client_secret: Option<PathBuf>,
    /// Beside this store, be attached to this node as a thin client (URL#KEY; needs --remote-secret):
    /// for the groups `group source` routes there
    #[arg(long, global = true, value_name = "ADDR", requires = "remote_secret", conflicts_with = "node")]
    pub remote: Option<String>,
    /// The file holding that thin client's secret (64 hex digits)
    #[arg(long = "remote-secret", global = true, value_name = "FILE", requires = "remote")]
    pub remote_secret: Option<PathBuf>,
}

/// Write flags of `set`, `replace`, `rm`, `op`.
#[derive(Args, Debug, Clone, Default)]
pub struct WriteFlags {
    /// Expire this write after DUR
    #[arg(long, value_name = "DUR")]
    pub expires_in: Option<String>,
    /// Expire this write at TS (RFC 3339 or ms)
    #[arg(long, value_name = "TS")]
    pub expires_at: Option<String>,
    /// Retention: by=NAME,at_least=DUR,at_least_abs=TS,at_most=DUR,at_most_abs=TS
    #[arg(long, value_name = "SPEC")]
    pub retention: Option<String>,
}

/// Commit query and undo scope.
#[derive(Args, Debug, Clone, Default)]
pub struct Scope {
    /// Every aspect of a thing
    #[arg(long, value_name = "T")]
    pub thing: Option<String>,
    /// These aspects (repeatable)
    #[arg(long, num_args = 2, value_names = ["T", "AK"], action = clap::ArgAction::Append)]
    pub aspect: Vec<String>,
    /// A group and everything in it
    #[arg(long, value_name = "G")]
    pub group: Option<String>,
}

/// Groups a new thing goes into (none: device-local, or a group synced itself).
#[derive(Args, Debug, Clone, Default)]
pub struct PlaceArgs {
    /// Item of group G
    #[arg(long = "in", value_name = "G")]
    pub in_: Option<String>,
    /// Item of each group (comma-separated)
    #[arg(long, value_name = "G,G", value_delimiter = ',')]
    pub in_all: Vec<String>,
}

/// Demotion flags.
#[derive(Args, Debug, Clone, Default)]
pub struct DemoteFlags {
    /// Pre-sync: required (default), try, skip
    #[arg(long, value_name = "MODE")]
    pub sync: Option<String>,
    /// Stamp the demotion at TS
    #[arg(long, value_name = "TS")]
    pub backdate: Option<String>,
    /// Repudiate the holder's rotations this device cannot open (a writer that locked everyone out)
    #[arg(long)]
    pub repudiate: bool,
    /// Override the edge: the removed holder's devices keep a read-only copy (true) or erase (false)
    #[arg(long, value_name = "BOOL")]
    pub keep: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a store: new device, person and home group
    Init {
        #[arg(long, value_name = "ADDR")]
        host: Vec<String>,
    },
    /// Restore a person on a fresh store from its recovery card
    Restore {
        /// The card, `@FILE` or `-` (stdin)
        card: String,
        #[arg(long, value_name = "ADDR")]
        host: Vec<String>,
    },
    /// This store's person, device, home group and hosts
    Whoami,
    /// Pair devices
    #[command(subcommand)]
    Pair(PairCmd),
    /// This person's devices
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Hosts this store syncs through
    #[command(subcommand)]
    Hosts(HostsCmd),
    /// What this node hosts (`host.0^`): show, set or stop it
    #[command(subcommand)]
    Hosting(HostingCmd),
    /// Thin clients this node serves (`clients.0^`)
    #[command(subcommand)]
    Clients(ClientsCmd),
    /// Keep the store open: sync, host as `host.0^` says (the flags write it, as `hosting set`;
    /// the host address prints first), print diagnostics
    Serve {
        #[command(flatten)]
        host: HostFlags,
        /// Serve thin clients at this URL, with the client listener's own key (repeatable): a
        /// line `client URL#KEY` per listener prints after the host address
        #[arg(long = "client-listen", value_name = "URL")]
        client_listen: Vec<String>,
    },
    /// Create a thing, optionally setting aspects: create --owner me --in home note:title.0 '"x"'
    Create(CreateArgs),
    /// Read an aspect (or a path in it); absent exits 3
    Get {
        t: String,
        ak: String,
        path: Option<String>,
        /// Copy a large string or blob raw to stdout
        #[arg(long)]
        stream: bool,
        /// Print the canonical size
        #[arg(long)]
        len: bool,
    },
    /// Make an aspect (or path) equal to VALUE: set T AK [PATH] VALUE
    Set(SetArgs),
    /// Reset, then write VALUE: replace T AK [PATH] VALUE
    Replace(SetArgs),
    /// Remove an aspect or a map entry, set element or list element
    Rm(RmArgs),
    /// A path op: insert I V.., delete A..B, move A..B TO, splice A..B S, undelete A..B, add V,
    /// remove-elem V, put K V, remove-key K, inc N, observe V, set-case ID [V]
    Op(OpArgs),
    /// Write only what changed from --base to the value on stdin ($EDITOR on a terminal)
    Edit {
        t: String,
        ak: String,
        path: Option<String>,
        /// What the script showed (required off a terminal)
        #[arg(long, value_name = "VALUE")]
        base: Option<String>,
    },
    /// Run a script from stdin as one commit (lines: create, set, replace, rm, op, place, unplace, sub, delete)
    Write,
    /// Every aspect of a thing, its groups and role
    Show {
        t: String,
        /// Truncate values to N chars (0: no limit)
        #[arg(long, default_value_t = 100)]
        width: usize,
    },
    /// Aspect keys of a thing
    Aspects { t: String },
    /// Delete every aspect and placement of a thing
    Delete { t: String },
    /// Things in a group
    Ls {
        g: String,
        #[arg(long, value_name = "AK")]
        with: Option<String>,
        #[arg(long, value_name = "time|PATH")]
        order: Option<String>,
        #[arg(long)]
        page: Option<usize>,
        #[arg(long)]
        follow: bool,
    },
    /// Things whose values reference T
    Backlinks {
        t: String,
        #[arg(long)]
        follow: bool,
    },
    /// Print changes of a thing (or one aspect), initial value first, until Ctrl-C
    Watch {
        t: String,
        ak: Option<String>,
        /// Stop after N changes (initial lines not counted)
        #[arg(long)]
        count: Option<usize>,
    },
    /// Held commits (anyone's), newest first
    Commits {
        #[command(flatten)]
        scope: Scope,
        /// By this actor (repeatable)
        #[arg(long, value_name = "A")]
        actor: Vec<String>,
        /// change, revert, role, snapshot or import (repeatable)
        #[arg(long, value_name = "KIND")]
        kind: Vec<String>,
        /// Reverts of commit C
        #[arg(long, value_name = "C")]
        reverts: Option<String>,
        /// The commit C reverts
        #[arg(long, value_name = "C")]
        reverted_by: Option<String>,
        /// Only commits in effect (true) or reverted (false)
        #[arg(long, value_name = "BOOL")]
        in_effect: Option<bool>,
        #[arg(long, value_name = "TS")]
        since: Option<String>,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        /// Page after commit C
        #[arg(long, value_name = "C")]
        after: Option<String>,
        #[arg(long = "max", value_name = "N")]
        max: Option<usize>,
        /// Only the change `undo` or `redo` in scope would revert now (needs a scope)
        #[arg(long, value_name = "undo|redo")]
        next: Option<String>,
    },
    /// Undo this person's newest change in scope
    Undo {
        #[command(flatten)]
        scope: Scope,
    },
    /// Redo this person's newest undo in scope
    Redo {
        #[command(flatten)]
        scope: Scope,
    },
    /// Revert any change by commit id
    Revert { id: String },
    /// Place T into group G
    Place { t: String, g: String },
    /// Remove T from group G
    Unplace { t: String, g: String },
    /// Subgroups
    #[command(subcommand)]
    Sub(SubCmd),
    /// Groups listing T as an item or a subgroup, and every group holding T (within)
    Groups { t: String },
    /// Holders of a thing with their edges (--watch: one line per change)
    Roster {
        t: String,
        #[arg(long)]
        watch: bool,
        /// With --watch: stop after N changes (the first line, the roster now, not counted)
        #[arg(long)]
        count: Option<usize>,
    },
    /// This device's role on T
    Role { t: String },
    /// The edges through which HOLDER is a holder of T (thing holder, one per line)
    Via { t: String, holder: String },
    /// The database's corrected clock
    Now,
    /// Grant HOLDER ROLE (read, write, admin) on T
    Grant {
        t: String,
        holder: String,
        role: String,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        #[arg(long, value_name = "ROLE")]
        invite: Option<String>,
        /// When the edge ends the holder's devices keep a read-only copy
        #[arg(long)]
        keep: bool,
    },
    /// Change an edge's until/invite or raise its role
    Edge {
        t: String,
        holder: String,
        #[arg(long)]
        role: Option<String>,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        #[arg(long, value_name = "ROLE")]
        invite: Option<String>,
        /// When the edge ends the holder's devices keep a read-only copy (true) or erase (false)
        #[arg(long, value_name = "BOOL")]
        keep: Option<bool>,
    },
    /// Lower HOLDER to ROLE or `remove` (after the pre-sync)
    Demote {
        t: String,
        holder: String,
        role: String,
        #[command(flatten)]
        d: DemoteFlags,
    },
    /// Remove this person's own edge on T
    Leave { t: String },
    /// List this device's kept read-only copies of what it was removed from, or erase ACTOR's
    Kept {
        #[arg(long, value_name = "ACTOR")]
        drop: Option<String>,
    },
    /// Place T in group G and give G a tied edge on T (it goes when the placement goes)
    ShareInto {
        t: String,
        g: String,
        role: String,
        /// Place T as a subgroup of G, not an item
        #[arg(long)]
        subgroup: bool,
        /// Place even when this node may not grant (T is then excluded)
        #[arg(long)]
        place_anyway: bool,
    },
    /// As an admin of group G, remove G's edge on T (a self-removal)
    RemoveEdgeOf { g: String, t: String },
    /// Per group listing T (or with a tied edge on it): tied, untied or excluded
    Reach { t: String },
    /// Share links
    #[command(subcommand)]
    Link(LinkCmd),
    /// Contact cards
    #[command(subcommand)]
    Card(CardCmd),
    /// Move T to a new owner (prints the new tid)
    Move {
        t: String,
        owner: String,
        #[command(flatten)]
        place: PlaceArgs,
    },
    /// Whether two tids name one thing (exit 3 if not)
    Same { a: String, b: String },
    /// Create an ownerless thing, ADMIN its first admin (prints its tid)
    Ownerless { admin: String },
    /// Connectivity and per-group sync state
    Status {
        #[arg(long)]
        watch: bool,
    },
    /// Sync now and wait until everything (or G) is at a host
    Sync {
        #[arg(long, value_name = "G")]
        group: Option<String>,
    },
    /// Wait until everything (or G) is at a host
    Wait {
        #[arg(long, value_name = "G")]
        group: Option<String>,
    },
    /// Group sync configuration
    #[command(subcommand)]
    Group(GroupCmd),
    /// Bundles
    #[command(subcommand)]
    Bundle(BundleCmd),
    /// Engine internals (format not stable)
    #[command(subcommand)]
    Inspect(InspectCmd),
    /// Diagnostics
    Diag {
        #[arg(long)]
        follow: bool,
    },
    /// Schemas registered with this store
    #[command(subcommand)]
    Schema(SchemaCmd),
}

#[derive(Args, Debug, Clone)]
pub struct CreateArgs {
    /// Owner actor (`me` usually)
    #[arg(long, value_name = "ACTOR")]
    pub owner: String,
    #[command(flatten)]
    pub place: PlaceArgs,
    /// Give it an empty group.0
    #[arg(long)]
    pub group: bool,
    /// Bind $NAME to the new tid (write scripts)
    #[arg(long = "as", value_name = "NAME")]
    pub as_: Option<String>,
    /// AK VALUE pairs
    #[arg(value_name = "AK VALUE", allow_hyphen_values = true)]
    pub pairs: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct SetArgs {
    pub t: String,
    pub ak: String,
    /// [PATH] VALUE ([PATH] with --stream)
    #[arg(num_args = 0..=2, required_unless_present = "stream", value_name = "[PATH] VALUE", allow_hyphen_values = true)]
    pub rest: Vec<String>,
    /// Read stdin into a blob/string position without materializing
    #[arg(long)]
    pub stream: bool,
    #[command(flatten)]
    pub w: WriteFlags,
}

#[derive(Args, Debug, Clone)]
pub struct RmArgs {
    pub t: String,
    pub ak: String,
    pub path: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct OpArgs {
    pub t: String,
    pub ak: String,
    /// Path ('' for the whole aspect)
    pub path: String,
    pub op: String,
    #[arg(allow_hyphen_values = true)]
    pub args: Vec<String>,
    #[command(flatten)]
    pub w: WriteFlags,
}

#[derive(Subcommand, Debug)]
pub enum PairCmd {
    /// Print an offer and wait for a device to join
    Offer,
    /// Join as a new device (fresh store)
    Join {
        offer: String,
        #[arg(long, value_name = "ADDR")]
        host: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    Ls,
    Rm {
        node: String,
        #[command(flatten)]
        d: DemoteFlags,
    },
}

#[derive(Subcommand, Debug)]
pub enum HostsCmd {
    Ls,
    Add { addr: String },
    Rm { addr: String },
}

#[derive(Subcommand, Debug)]
pub enum ClientsCmd {
    /// Registers a thin client: prints `ACTOR SECRET`, the secret (64 hex digits) only here. Grant
    /// the actor what it may reach
    Add {
        /// When it ends (as `share --until`)
        #[arg(long)]
        until: Option<String>,
    },
    /// List them: `ACTOR UNTIL|-`
    Ls,
    /// Revoke one: closes its connections, removes its grants (with their rotations) and its
    /// entry (none: exit 3)
    Rm { actor: String },
    /// A new secret for one (printed only here); the old one and its connections end
    Rotate { actor: String },
    /// A new client listener key: clients need the new addresses, printed here; through a daemon
    /// its listeners and clients move at once
    RotateKey,
}

#[derive(Subcommand, Debug)]
pub enum HostingCmd {
    /// Print `host.0^` (not hosting: exit 3)
    Show,
    /// Start or change hosting: each flag given replaces its field, the rest kept
    Set(HostFlags),
    /// Stop hosting (the host address is dropped; a later start has a new one)
    Off,
}

/// `host.0^` fields (`hosting set`, `serve`): each flag given replaces its field; a flag given
/// once as `''` clears it.
#[derive(clap::Args, Debug, Default)]
pub struct HostFlags {
    /// Listen for hosted sessions at this transport URL (repeatable)
    #[arg(long, value_name = "URL")]
    pub listen: Vec<String>,
    /// Which labels this node takes: those of groups its person owns naming its host address,
    /// or any
    #[arg(long, value_enum)]
    pub admit: Option<AdmitArg>,
    /// Also admit a group's labels (a group synced here) or a label ID, 32 hex digits
    /// (repeatable)
    #[arg(long, value_name = "GROUP|ID")]
    pub label: Vec<String>,
    /// Push hosted labels to this peer host, `url#key` (repeatable)
    #[arg(long, value_name = "ADDR")]
    pub replicate: Vec<String>,
    /// A host policy knob (repeatable)
    #[arg(long, value_name = "NAME=N")]
    pub policy: Vec<String>,
    /// Caps for a group's labels or a label ID, in place of the policy's (repeatable)
    #[arg(long, value_name = "GROUP|ID=ENTRIES,BYTES")]
    pub cap: Vec<String>,
}

impl HostFlags {
    pub fn any(&self) -> bool {
        !self.listen.is_empty() || self.admit.is_some() || !self.label.is_empty() || !self.replicate.is_empty() || !self.policy.is_empty() || !self.cap.is_empty()
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum SubCmd {
    Add { g: String, sub: String },
    Rm { g: String, sub: String },
}

#[derive(Subcommand, Debug)]
pub enum LinkCmd {
    Make {
        t: String,
        role: String,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        #[arg(long)]
        single_use: bool,
        /// Joiners' devices keep a read-only copy when removed
        #[arg(long)]
        keep: bool,
    },
    Redeem { link: String },
    Ls { t: String },
    /// End link ID; with --joiner, also remove that joiner in the same commit
    Revoke {
        id: String,
        #[arg(long, value_name = "ACTOR")]
        joiner: Option<String>,
        #[command(flatten)]
        d: DemoteFlags,
    },
}

#[derive(Subcommand, Debug)]
pub enum CardCmd {
    Show,
    Import { card: String },
    /// This person's profile thing, or the profile a card import brought for PERSON
    Profile { person: Option<String> },
}

#[derive(Subcommand, Debug)]
pub enum GroupCmd {
    /// Make G synced (default: the store's hosts)
    Sync {
        g: String,
        #[arg(long, value_name = "ADDR")]
        host: Vec<String>,
    },
    Unsync { g: String },
    /// Where G's calls go: `local`, or ADDR (URL#KEY) of the node attached by --remote; held in the
    /// store. Local: this store syncs it, and it is caught up before calls come home
    Source { g: String, to: String },
    Policy {
        g: String,
        #[arg(long, value_name = "BOOL")]
        publish_reach: Option<bool>,
        #[arg(long, value_name = "BOOL")]
        heartbeats: Option<bool>,
    },
}

#[derive(Subcommand, Debug)]
pub enum BundleCmd {
    /// Write groups as a bundle to stdout
    Export { groups: Vec<String> },
    /// Read a bundle from stdin
    Import,
}

#[derive(Subcommand, Debug)]
pub enum InspectCmd {
    Thing { t: String },
    Group { g: String },
    Actor { a: String },
    Commit { id: String },
}

#[derive(Subcommand, Debug)]
pub enum SchemaCmd {
    /// Register a schema file with this store
    Add { file: PathBuf },
    Rm { file: PathBuf },
    Ls,
    /// Parse and check against FILE.lock
    Check { file: PathBuf },
    /// Generate Rust into DIR
    Gen {
        file: PathBuf,
        #[arg(short, value_name = "DIR")]
        o: PathBuf,
    },
}

/// One line of a `write` script.
#[derive(Parser, Debug)]
#[command(name = "write-line", no_binary_name = true, disable_help_flag = true)]
pub struct ScriptLine {
    #[command(subcommand)]
    pub cmd: ScriptCmd,
}

#[derive(Subcommand, Debug)]
pub enum ScriptCmd {
    Create(CreateArgs),
    Set(SetArgs),
    Replace(SetArgs),
    Rm(RmArgs),
    Op(OpArgs),
    Place { t: String, g: String },
    Unplace { t: String, g: String },
    #[command(subcommand)]
    Sub(SubCmd),
    Delete { t: String },
}

/// `--admit`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitArg {
    Own,
    Open,
}
