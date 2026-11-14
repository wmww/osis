//! Status (spec/sync-status.md).
//!
//! State: complete passes begun per S; held-elsewhere reports (durable, kept while the entry
//! is); the view as of the last settle. Settle keeps the view and tells the engine of complete
//! passes and own commits held elsewhere; reading the view or a wait makes no output. Depends on
//! opens, streams, read, engine. Not built: every call below.

use crate::opens::Opens;
use crate::read::Read;
use crate::streams::Streams;
use crate::types::{Cx, Result, Scope, Waiting};
use osis_base::WallMs;
use osis_engine::Engine;
use std::sync::Arc;

/// Status now, per S: sources and their state, passes waiting; idle (spec/sync-status.md §3).
/// A memo value; its fields are the status owner's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusView {
    /// No request, fill or Hello outstanding on any connection.
    pub idle: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Status {
    view: Arc<StatusView>,
}

impl Status {
    pub fn view(&self) -> Arc<StatusView> {
        self.view.clone()
    }

    pub fn wait(&self, engine: &mut Engine, scope: Scope) -> Waiting {
        let _ = (engine, scope);
        Waiting::Never("status::wait not built")
    }

    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, opens: &Opens, streams: &Streams, read: &Read) -> Result<bool> {
        let _ = (cx, opens, streams, read);
        Ok(false)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}
