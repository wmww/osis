//! The command tree (plans/cli.md §4; notes/cli.md). Help text stays terse.

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
    /// Engine logs on stderr (-vv: more)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Materialization bound in bytes
    #[arg(long, global = true, value_name = "BYTES")]
    pub limit: Option<usize>,
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

/// Undo and history scope.
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

/// Where a new thing syncs.
#[derive(Args, Debug, Clone, Default)]
pub struct PlaceArgs {
    /// Item of group G
    #[arg(long = "in", value_name = "G")]
    pub in_: Option<String>,
    /// Item of each group (comma-separated)
    #[arg(long, value_name = "G,G", value_delimiter = ',')]
    pub in_all: Vec<String>,
    /// Device-local (or a group synced itself)
    #[arg(long)]
    pub unsynced: bool,
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
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a store: new device, person and home group
    Init {
        #[arg(long, value_name = "ADDR")]
        server: Vec<String>,
    },
    /// Restore a person on a fresh store from its recovery card
    Restore {
        card: String,
        #[arg(long, value_name = "ADDR")]
        server: Vec<String>,
    },
    /// This store's person, device, home group and servers
    Whoami,
    /// Pair devices
    #[command(subcommand)]
    Pair(PairCmd),
    /// This person's devices
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Servers this store syncs through
    #[command(subcommand)]
    Server(ServerCmd),
    /// Run a blind server (prints its address first)
    Serve {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        #[arg(long, value_name = "URL")]
        listen: Option<String>,
        #[arg(long, value_name = "DIR")]
        data: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
    },
    /// Create a thing, optionally setting aspects: create --owner me --in home /note/title '"x"'
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
        /// Stop after N lines
        #[arg(long)]
        count: Option<usize>,
    },
    /// Signals
    #[command(subcommand)]
    Signal(SignalCmd),
    /// Everyone's changes in scope, newest first
    History {
        #[command(flatten)]
        scope: Scope,
        #[arg(long = "max", value_name = "N", default_value_t = 100)]
        max: usize,
        #[arg(long, value_name = "TS")]
        before: Option<String>,
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
    /// Undo any change by commit id
    UndoCommit { id: String },
    /// Place T into group G
    Place { t: String, g: String },
    /// Remove T from group G
    Unplace { t: String, g: String },
    /// Subgroups
    #[command(subcommand)]
    Sub(SubCmd),
    /// Groups T is in
    Groups { t: String },
    /// Members of a thing with their edges (--watch: one line per change)
    Roster {
        t: String,
        #[arg(long)]
        watch: bool,
        /// With --watch: stop after N lines
        #[arg(long)]
        count: Option<usize>,
    },
    /// This device's role on T
    Role { t: String },
    /// Grant MEMBER ROLE (read, write, admin) on T
    Grant {
        t: String,
        member: String,
        role: String,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        #[arg(long, value_name = "ROLE")]
        invite: Option<String>,
    },
    /// Change an edge's until/invite or raise its role
    Edge {
        t: String,
        member: String,
        #[arg(long)]
        role: Option<String>,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        #[arg(long, value_name = "ROLE")]
        invite: Option<String>,
    },
    /// Lower MEMBER to ROLE or `remove` (after the pre-sync)
    Demote {
        t: String,
        member: String,
        role: String,
        #[command(flatten)]
        d: DemoteFlags,
    },
    /// Remove this person's own edge on T
    Leave { t: String },
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
    /// Connectivity and per-group sync state
    Status {
        #[arg(long)]
        watch: bool,
    },
    /// Sync now and wait until everything (or G) is at a server
    Sync {
        #[arg(long, value_name = "G")]
        group: Option<String>,
    },
    /// Wait until everything (or G) is at a server
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
    /// Keep the store open: sync, print diagnostics
    Daemon,
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
    /// Give it an empty /group
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
    /// [PATH] VALUE
    #[arg(num_args = 1..=2, required = true, value_name = "[PATH] VALUE", allow_hyphen_values = true)]
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
        server: Vec<String>,
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
pub enum ServerCmd {
    Ls,
    Add { addr: String },
    Rm { addr: String },
}

#[derive(Subcommand, Debug)]
pub enum SignalCmd {
    /// Send a signal about T
    Send {
        t: String,
        kind: String,
        value: String,
        #[arg(long, value_name = "NODE")]
        to: Option<String>,
    },
    /// Print signals about T
    Listen {
        t: String,
        kind: String,
        #[arg(long)]
        count: Option<usize>,
    },
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
    },
    Redeem { link: String },
    Ls { t: String },
    Revoke {
        id: String,
        #[command(flatten)]
        d: DemoteFlags,
    },
}

#[derive(Subcommand, Debug)]
pub enum CardCmd {
    Show,
    Import { card: String },
}

#[derive(Subcommand, Debug)]
pub enum GroupCmd {
    /// Make G synced (default: the store's servers)
    Sync {
        g: String,
        #[arg(long, value_name = "ADDR")]
        server: Vec<String>,
    },
    Unsync { g: String },
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
