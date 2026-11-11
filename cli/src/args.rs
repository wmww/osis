//! The command tree (notes/cli.md Command table; notes/cli.md). Help text stays terse.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Entries a command asks for at a time. Minor: the next page follows; 0 reads nothing, past what
/// the API's page holds it holds that.
pub const PAGE: usize = 256;

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
    /// Do not announce this node on the local network or look for others there
    #[arg(long = "no-lan", global = true)]
    pub no_lan: bool,
    /// Materialization bound in bytes
    #[arg(long, global = true, value_name = "BYTES")]
    pub limit: Option<usize>,
    /// Run the command at this node as a thin client (URL#KEY; needs --client-secret, no store)
    #[arg(long, global = true, value_name = "ADDR", requires = "client_secret")]
    pub node: Option<String>,
    /// The file holding the thin client's secret (64 hex digits, as `clients add` printed it)
    #[arg(long = "client-secret", global = true, value_name = "FILE", requires = "node")]
    pub client_secret: Option<PathBuf>,
    /// Beside this store, connect to this node as its client (URL#KEY; needs --connect-secret):
    /// for the groups whose `group source` it is
    #[arg(long, global = true, value_name = "ADDR", requires = "connect_secret", conflicts_with = "node")]
    pub connect: Option<String>,
    /// The file holding that client's secret (64 hex digits)
    #[arg(long = "connect-secret", global = true, value_name = "FILE", requires = "connect")]
    pub connect_secret: Option<PathBuf>,
}

/// Write flags of `set`, `overwrite`, `rm`, `op`.
#[derive(Args, Debug, Clone, Default)]
pub struct WriteFlags {
    /// The commit expires after DUR
    #[arg(long, value_name = "DUR")]
    pub expires_in: Option<String>,
    /// The commit expires at TS (RFC 3339 or ms)
    #[arg(long, value_name = "TS", conflicts_with = "expires_in")]
    pub expires_at: Option<String>,
    /// Retention: by=NAME,keep_history=forever|DUR,keep_until=TS,purge_on_replace
    #[arg(long, value_name = "SPEC")]
    pub retention: Option<String>,
}

/// Where commits are listed, and undo's scope.
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

/// A page of commits and its filters, or `--follow`.
#[derive(Args, Debug, Clone, Default)]
pub struct ListArgs {
    /// Oldest first
    #[arg(long, conflicts_with_all = ["before", "after"])]
    pub oldest: bool,
    /// Older than this place (`pos` of a line printed)
    #[arg(long, value_name = "POS", conflicts_with = "after")]
    pub before: Option<String>,
    /// Newer than this place, oldest first
    #[arg(long, value_name = "POS")]
    pub after: Option<String>,
    #[arg(long = "max", value_name = "N", default_value_t = PAGE)]
    pub max: usize,
    /// By this actor (repeatable)
    #[arg(long, value_name = "A")]
    pub actor: Vec<String>,
    /// content, revert, role or snapshot (repeatable)
    #[arg(long, value_name = "KIND")]
    pub kind: Vec<String>,
    /// Reverts of commit C
    #[arg(long, value_name = "C")]
    pub reverts: Option<String>,
    /// The commit C reverts
    #[arg(long, value_name = "C")]
    pub reverted_by: Option<String>,
    /// Only commits in effect (true) or reverted (false)
    #[arg(long, value_name = "BOOL")]
    pub in_effect: Option<bool>,
    /// Print each commit that reads otherwise from now on, until Ctrl-C
    #[arg(long, conflicts_with_all = ["oldest", "before", "after"])]
    pub follow: bool,
    /// With --follow: stop after N commits
    #[arg(long, requires = "follow")]
    pub count: Option<usize>,
}

/// Groups a new thing goes into (none: on this node alone, or a group synced itself).
#[derive(Args, Debug, Clone, Default)]
pub struct GroupsArgs {
    /// Item of group G
    #[arg(long = "in", value_name = "G")]
    pub in_: Option<String>,
    /// Item of each group (comma-separated)
    #[arg(long, value_name = "G,G", value_delimiter = ',')]
    pub in_all: Vec<String>,
}

/// How a role is taken away.
#[derive(Args, Debug, Clone, Default)]
pub struct SetRoleFlags {
    /// On a removal: the removed holder's nodes retain a read-only copy (true) or erase it (false); default: the thing's (`required^.0`, field retain)
    #[arg(long = "retain-copy", value_name = "BOOL")]
    pub retain_copy: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create a store: a new node, account and home group
    Init {
        /// A peer to sync with (repeatable)
        #[arg(long, value_name = "ADDR")]
        peer: Vec<String>,
    },
    /// This store's account (also its home group), node and saved peers
    Whoami,
    /// Add a node to this account
    #[command(subcommand)]
    Pair(PairCmd),
    /// This account's nodes
    #[command(subcommand)]
    Node(NodeCmd),
    /// Nodes this store syncs with
    #[command(subcommand)]
    Peers(PeersCmd),
    /// Whether this node stores and serves data for others, and on what terms: show, set or stop it
    #[command(subcommand)]
    Serving(ServingCmd),
    /// Thin clients of this node, each with an actor of its own
    #[command(subcommand)]
    Clients(ClientsCmd),
    /// Keep the store open: sync, serve data for others if set to (the flags set it, as `serving set`;
    /// the serving address prints first), print diagnostics
    Serve {
        #[command(flatten)]
        serving: ServingFlags,
        /// Serve clients at this URL, with the client listener's own key (repeatable): a
        /// line `client URL#KEY` per listener prints after the serving address
        #[arg(long = "client-listen", value_name = "URL")]
        client_listen: Vec<String>,
    },
    /// Create a thing, optionally setting aspects: create --in home note:title.0 '"x"'
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
    /// Write VALUE whole, always, in place of what is there: overwrite T AK [PATH] VALUE
    Overwrite(SetArgs),
    /// Fire a signal (a `~` key) with VALUE: fire T AK VALUE
    Fire(FireArgs),
    /// Remove an aspect or a map entry, set element or list element
    Rm(RmArgs),
    /// A path op: splice A..B [V..] (a text position: splice A..B S), move A..B TO, undelete A..B,
    /// add V, contribute N
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
    /// Run a script from stdin as one commit (lines: create, set, overwrite, rm, op, group add, group rm, delete)
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
    /// Delete every aspect and membership of a thing
    Delete { t: String },
    /// Things in a group, by query (not built yet: `members` lists them)
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
    /// Things whose values reference T (not built yet)
    Backlinks {
        t: String,
        #[arg(long)]
        follow: bool,
    },
    /// Print changes of a thing (or one aspect, or the value at PATH in it, as `get` reads it),
    /// initial value first, until Ctrl-C
    Watch {
        t: String,
        ak: Option<String>,
        path: Option<String>,
        /// Stop after N changes (initial lines not counted)
        #[arg(long)]
        count: Option<usize>,
    },
    /// Commits listed at an address (a value aspect `T AK`, or a scope), newest first, each with
    /// its parts: one line per commit
    Writes {
        /// The thing of one value aspect (with AK)
        t: Option<String>,
        ak: Option<String>,
        #[command(flatten)]
        scope: Scope,
        #[command(flatten)]
        list: ListArgs,
        /// Only the commit `undo` or `redo` in scope would revert now (needs a scope)
        #[arg(long, value_name = "undo|redo", conflicts_with = "follow")]
        next: Option<String>,
    },
    /// Fires of the signal AK of T, newest first, each with its parts: one line per commit. A fire
    /// its author replaced shows its newest text, with `edited=POS`
    Fired {
        t: String,
        ak: String,
        #[command(flatten)]
        list: ListArgs,
        /// The versions of fire C instead, each as written: C first, then its replacements
        #[arg(long, value_name = "C", conflicts_with = "follow")]
        versions_of: Option<String>,
    },
    /// Purge an aspect's history, one commit's write or an author's writes, each where this actor may
    Purge {
        t: String,
        ak: String,
        /// Only this commit's write
        #[arg(long, value_name = "C", conflicts_with = "author")]
        commit: Option<String>,
        /// Only this actor's writes stamped before now, also those arriving later
        #[arg(long, value_name = "A")]
        author: Option<String>,
    },
    /// Undo this account's newest commit in scope
    Undo {
        #[command(flatten)]
        scope: Scope,
    },
    /// Redo this account's newest undo in scope
    Redo {
        #[command(flatten)]
        scope: Scope,
    },
    /// Revert any commit by its id
    Revert { id: String },
    /// Groups listing T as an item or a subgroup, and every group holding T (within)
    Groups { t: String },
    /// What group G contains: its items and subgroups
    Members { g: String },
    /// The roles granted on T, by holder (--watch: one line per change)
    Grants {
        t: String,
        #[arg(long)]
        watch: bool,
        /// With --watch: stop after N changes (the first line, the grants now, not counted)
        #[arg(long)]
        count: Option<usize>,
    },
    /// This node's role on T
    Role { t: String },
    /// Everyone holding a role on T, directly or through another actor: actor, role, when it ends,
    /// and the actors in between, one line per grant that makes it a holder
    Holders { t: String },
    /// This node's corrected clock
    Now,
    /// Grant HOLDER ROLE (read, write, admin) on T, or change the grant's --until and --may-grant (no
    /// ROLE: as it is). Never lowers. Records the role only: HOLDER reads T once a synced group it
    /// reads holds T or T syncs (`group sync`); `status` shows otherwise
    Grant {
        t: String,
        holder: String,
        role: Option<String>,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        /// The highest role HOLDER may grant others
        #[arg(long = "may-grant", value_name = "ROLE")]
        may_grant: Option<String>,
    },
    /// Make HOLDER's role on T this one: read, write, admin, or none to remove
    SetRole {
        t: String,
        holder: String,
        role: String,
        #[command(flatten)]
        d: SetRoleFlags,
    },
    /// Remove this account's own grant on T, or with --holder that of an actor this node is an
    /// admin of (no catching up)
    Leave {
        t: String,
        #[arg(long, value_name = "ACTOR")]
        holder: Option<String>,
    },
    /// List this node's read-only copies of what it was removed from, or erase ACTOR's
    Retained {
        #[arg(long, value_name = "ACTOR")]
        drop: Option<String>,
    },
    /// Add T to group G and grant G ROLE on it, tied together: the grant goes when T leaves G
    AddWithGrant {
        t: String,
        g: String,
        role: String,
        /// T joins as a subgroup of G, not an item
        #[arg(long)]
        subgroup: bool,
    },
    /// Share links
    #[command(subcommand)]
    Link(LinkCmd),
    /// Contact cards
    #[command(subcommand)]
    Card(CardCmd),
    /// Group chat
    #[command(subcommand)]
    Chat(ChatCmd),
    /// Admin disputes: fights this node settles for itself
    #[command(subcommand)]
    Disputes(DisputeCmd),
    /// Sync connections up, then how each group's sync stands
    Status {
        #[arg(long)]
        watch: bool,
    },
    /// Sync now and wait until everything (or G) is caught up with every connected node; with nobody connected it waits (until --timeout)
    Sync {
        #[arg(long, value_name = "G")]
        group: Option<String>,
    },
    /// Wait until everything (or G) is caught up with every connected node; with nobody connected it waits (until --timeout)
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
    /// First admin in place of the acting actor: a thin client's way to create, naming a group that outlives it
    #[arg(long, value_name = "G")]
    pub admin: Option<String>,
    #[command(flatten)]
    pub groups: GroupsArgs,
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
pub struct FireArgs {
    pub t: String,
    pub ak: String,
    #[arg(allow_hyphen_values = true)]
    pub value: String,
    /// Replace this actor's fire C with VALUE (C as `fired` prints it)
    #[arg(long, value_name = "C")]
    pub replaces: Option<String>,
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
pub enum DisputeCmd {
    /// List them: `ID TARGET AUTHOR HOLDER SIDE [chosen]` for a removal, `ID VERSIONS SIDE
    /// [chosen]` for an account's history, then how many removals were not examined
    Ls,
    /// Take a side: of a removal `author` (it counts) or `holder` (it does not); of an account's
    /// history the commit ID a version ends in
    Choose { id: String, side: String },
}

#[derive(Subcommand, Debug)]
pub enum PairCmd {
    /// Print an offer and wait for a new node to join
    Offer,
    /// Join as a new node (fresh store)
    Join {
        offer: String,
        /// A peer to sync with (repeatable)
        #[arg(long, value_name = "ADDR")]
        peer: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum NodeCmd {
    /// List them: `NODE ROLE`
    Ls,
    /// Remove a node from this account, listing the links it can still use
    Rm {
        // its own id: `node` is the global `--node`'s, whose value this would become
        #[arg(id = "removed_node", value_name = "NODE")]
        node: String,
        #[command(flatten)]
        d: SetRoleFlags,
        /// Also end the account's links: the node keeps their seeds. Without it they are listed
        #[arg(long)]
        end_links: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PeersCmd {
    /// The saved peers; with --group, whom G syncs with: its saved peers and readers' published addresses
    Ls {
        #[arg(long, value_name = "G")]
        group: Option<String>,
    },
    /// Save a peer, a node serving at ADDR (its `serving show`): what syncs from now on syncs with it
    Add { addr: String },
    /// Remove a saved peer
    Rm { addr: String },
}

#[derive(Subcommand, Debug)]
pub enum ClientsCmd {
    /// Registers a client: prints `ACTOR SECRET`, the secret (64 hex digits) only here. Grant
    /// the actor what it may reach
    Add {
        /// When it ends (as `grant --until`)
        #[arg(long)]
        until: Option<String>,
    },
    /// List them: `ACTOR UNTIL|-`
    Ls,
    /// Remove one: closes its connections, removes its grants and its
    /// entry (none: exit 3)
    Rm { actor: String },
    /// A new secret for one (printed only here); the old one and its connections end
    Rotate { actor: String },
    /// A new client listener key: clients need the new addresses, printed here; through a daemon
    /// its listeners and clients move at once
    RotateAddress,
}

#[derive(Subcommand, Debug)]
pub enum ServingCmd {
    /// Print the terms (not serving: exit 3)
    Show,
    /// Start or change serving: each flag given replaces its field, the rest kept
    Set(ServingFlags),
    /// The sync IDs of a synced group, for a serving node's `--admitted` and `--cap`, one per line
    Ids { g: String },
    /// Stop serving (what was stored and the serving address are dropped; a later start has a new one)
    Off,
}

/// The terms of serving (`serving set`, `serve`): each flag given replaces its field; a flag given
/// once as `''` clears it.
#[derive(clap::Args, Debug, Default)]
pub struct ServingFlags {
    /// Listen at this transport URL (repeatable)
    #[arg(long, value_name = "URL")]
    pub listen: Vec<String>,
    /// Which groups this node takes: its own (made under it or its account) naming its serving address, or any
    #[arg(long, value_enum)]
    pub admit: Option<AdmitArg>,
    /// Also admit a group (one synced here) or a sync ID, 32 hex digits (repeatable)
    #[arg(long, value_name = "GROUP|ID")]
    pub admitted: Vec<String>,
    /// Push what it stores for others to this serving node, `url#key` (repeatable)
    #[arg(long, value_name = "ADDR")]
    pub replicate: Vec<String>,
    /// A limit: group_entries, group_bytes, groups, entries, bytes, connections (repeatable)
    #[arg(long, value_name = "NAME=N")]
    pub policy: Vec<String>,
    /// Caps for a group or a sync ID, in place of the policy's (repeatable)
    #[arg(long, value_name = "GROUP|ID=ENTRIES,BYTES")]
    pub cap: Vec<String>,
}

impl ServingFlags {
    pub fn any(&self) -> bool {
        !self.listen.is_empty() || self.admit.is_some() || !self.admitted.is_empty() || !self.replicate.is_empty() || !self.policy.is_empty() || !self.cap.is_empty()
    }
}

/// A group's members (`group add`, `group rm`).
#[derive(Subcommand, Debug, Clone)]
pub enum MemberCmd {
    /// Add T to group G: an item, or with --subgroup a subgroup
    Add {
        g: String,
        t: String,
        #[arg(long)]
        subgroup: bool,
        /// The commit, so the membership, expires after DUR
        #[arg(long, value_name = "DUR")]
        expires_in: Option<String>,
        /// The commit, so the membership, expires at TS (RFC 3339 or ms)
        #[arg(long, value_name = "TS", conflicts_with = "expires_in")]
        expires_at: Option<String>,
    },
    /// Remove T from group G: an item, or with --subgroup a subgroup
    Rm {
        g: String,
        t: String,
        #[arg(long)]
        subgroup: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum LinkCmd {
    /// Make a link giving ROLE on T, and sync T if it does not yet; prints the link
    Make {
        t: String,
        role: String,
        #[arg(long, value_name = "TS")]
        until: Option<String>,
        #[arg(long)]
        single_use: bool,
    },
    /// Join what LINK names; prints the thing
    Redeem { link: String },
    /// The account's working links (of thing T)
    Ls { t: Option<String> },
    /// End link ID (a join no writer received yet is undone)
    Revoke { id: String },
}

#[derive(Subcommand, Debug)]
pub enum ChatCmd {
    /// A new chat, this account its admin: prints its tid
    Create {
        #[arg(long, default_value = "")]
        name: String,
        /// Who deletes: author-or-admin, author, admin, nobody
        #[arg(long, default_value = "author-or-admin")]
        purge: String,
        /// What an edit does to the old text: purge, keep, off
        #[arg(long, default_value = "purge")]
        edit: String,
        /// Messages disappear after DUR
        #[arg(long, value_name = "DUR")]
        disappear: Option<String>,
        /// A kicked participant erases what it holds, unless the kick says otherwise
        #[arg(long)]
        no_retain_copy: bool,
        /// Who it syncs with (default: the store's saved peers); another account's serving node must admit it (`admit own` takes only the maker's)
        #[arg(long, value_name = "ADDR")]
        peer: Vec<String>,
    },
    /// Adds an account (a tid from `card import`)
    Add {
        chat: String,
        account: String,
        #[arg(long, default_value = "write")]
        role: String,
    },
    /// A link to join by: prints it
    Link {
        chat: String,
        #[arg(long, default_value = "write")]
        role: String,
        #[arg(long)]
        single_use: bool,
    },
    /// Joins by link: prints the chat's tid
    Join { link: String },
    /// Removes a participant
    Kick {
        chat: String,
        account: String,
        /// They erase what they hold, whatever the chat's default
        #[arg(long)]
        erase: bool,
        /// They retain a read-only copy, whatever the chat's default
        #[arg(long, conflicts_with = "erase")]
        retain_copy: bool,
        /// Also erase everything they sent
        #[arg(long)]
        purge: bool,
    },
    /// Sends a message (TEXT, `@FILE`, or `-` for stdin): prints its id
    Post {
        chat: String,
        text: String,
        /// A first line before the text
        #[arg(long)]
        subject: Option<String>,
        /// The name to show
        #[arg(long = "from", env = "OSIS_CHAT_NAME")]
        from: Option<String>,
        /// The message it answers
        #[arg(long, value_name = "ID")]
        reply_to: Option<String>,
    },
    /// Messages, oldest first; the newest MAX, or those after a cursor
    Read {
        chat: String,
        #[arg(long, default_value_t = 50)]
        max: usize,
        /// Only older than this message
        #[arg(long, value_name = "ID", conflicts_with = "after")]
        before: Option<String>,
        /// Only what arrived here after this cursor (printed last, as `cursor CURSOR`)
        #[arg(long, value_name = "CURSOR")]
        after: Option<String>,
    },
    /// Changes as they come: first what lies after `--after`, then new ones
    Watch {
        chat: String,
        /// Stop after N
        #[arg(long)]
        count: Option<usize>,
        #[arg(long, value_name = "CURSOR")]
        after: Option<String>,
    },
    /// Replaces one's own message (its id stays)
    Edit { chat: String, id: String, text: String },
    /// Sends one's own undelivered message again
    Resend { chat: String, id: String },
    /// Deletes a message for everyone
    Delete { chat: String, id: String },
    Leave { chat: String },
    /// Who takes part in what role (a link joiner: via its link), the links that work, and the chat's settings
    Participants { chat: String },
    /// The disappearing timer: DUR, or `off`
    Disappear { chat: String, after: String },
}

#[derive(Subcommand, Debug)]
pub enum CardCmd {
    Show,
    Import { card: String },
    /// This account's profile thing, or the profile a card import brought for ACCOUNT
    Profile { account: Option<String> },
}

#[derive(Subcommand, Debug)]
pub enum GroupCmd {
    #[command(flatten)]
    Member(MemberCmd),
    /// Make G synced (default: the store's saved peers)
    Sync {
        g: String,
        /// A peer to sync with (repeatable)
        #[arg(long, value_name = "ADDR")]
        peer: Vec<String>,
    },
    /// Where G's calls go: shows it, or moves it to TO: `local`, or ADDR (URL#KEY) of the node
    /// connected by --connect; held in the store. Local: this store syncs it, and it is caught up
    /// before calls come home
    Source { g: String, to: Option<String> },
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
    /// Parse and validate a schema file
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
    Overwrite(SetArgs),
    Fire(FireArgs),
    Rm(RmArgs),
    Op(OpArgs),
    #[command(subcommand)]
    Group(MemberCmd),
    Delete { t: String },
}

/// `--admit`.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmitArg {
    Own,
    Open,
}
