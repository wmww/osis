//! The sources of each read S as read sees them (`Ground::source`, `sources`, `sources_added`):
//! per (S, source) the connections it is open on and whether it keeps S unread, written as opens
//! reports each member joining or leaving (`Moved`, handed by the driver), every write stamped and
//! fed, so a source joining or leaving moves only the judgements that read it.

use super::ground::SrcView;
use crate::opens::{Moved, Opens};
use crate::store::Source;
use crate::types::{ConnId, SourceClass};
use osis_base::SyncId;
use osis_base::memo::{Feed, Stamps};
use std::collections::BTreeMap;

/// A view row as `Views::feed` names it.
pub type Row = (&'static str, SyncId, Source);

#[derive(Clone, Debug, Default)]
pub struct Views {
    /// Per (S, source), each connection it is open on and whether it is a store source there.
    open: BTreeMap<SyncId, BTreeMap<Source, BTreeMap<ConnId, bool>>>,
    /// Where each (connection, S) member's rows live, as it joined.
    by_conn: BTreeMap<(ConnId, SyncId), Source>,
    stamps: Stamps,
}

impl Views {
    /// A member moved (opens' word, through the driver).
    pub fn moved(&mut self, m: &Moved, opens: &Opens) {
        match m {
            Moved::Joined(conn, s, _) => {
                let store = opens.members(*conn).get(s).is_some_and(|x| x.class == SourceClass::Store);
                let at = opens.record(*conn).map_or(Source::Conn(*conn), Source::Record);
                if let Some(old) = self.by_conn.insert((*conn, *s), at) {
                    self.drop_conn(*s, old, *conn);
                }
                if !self.open.contains_key(s) {
                    self.stamps.wrote(&("any", *s), true);
                }
                self.open.entry(*s).or_default().entry(at).or_default().insert(*conn, store);
                self.wrote(*s, at);
            }
            Moved::Left(conn, s, _) => {
                if let Some(at) = self.by_conn.remove(&(*conn, *s)) {
                    self.drop_conn(*s, at, *conn);
                }
            }
            Moved::Until(..) => {}
        }
    }

    fn drop_conn(&mut self, s: SyncId, at: Source, conn: ConnId) {
        if let Some(by) = self.open.get_mut(&s) {
            if let Some(m) = by.get_mut(&at) {
                m.remove(&conn);
                if m.is_empty() {
                    by.remove(&at);
                }
            }
            if by.is_empty() {
                self.open.remove(&s);
                self.stamps.wrote(&("any", s), true);
            }
        }
        self.wrote(s, at);
    }

    fn wrote(&self, s: SyncId, at: Source) {
        self.stamps.wrote_added(&("v", s, at), true, true);
        self.stamps.wrote(&("s", s), true);
    }

    /// Source `at` of S, if open on a connection up now; its head, full and role flags are the
    /// caller's to fill.
    pub fn get(&self, s: &SyncId, at: &Source) -> Option<SrcView> {
        self.stamps.read(&("v", *s, *at));
        let (conn, store) = self.open.get(s)?.get(at)?.iter().next().map(|(c, x)| (*c, *x))?;
        Some(SrcView { at: *at, conn, store, head: None, full: false, role_unheld: false })
    }

    /// Every source of S up now.
    pub fn of(&self, s: &SyncId) -> Vec<Source> {
        self.stamps.read(&("s", *s));
        self.open.get(s).map(|by| by.keys().copied().collect()).unwrap_or_default()
    }

    /// Some source of S is up now: moves only when that flips.
    pub fn any(&self, s: &SyncId) -> bool {
        self.stamps.read(&("any", *s));
        self.open.contains_key(s)
    }

    /// A cursor over the views written from now on.
    pub fn feed(&self) -> Feed<Row> {
        self.stamps.feed()
    }
}
