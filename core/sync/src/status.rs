//! Status (spec/sync-status.md).
//!
//! State: complete passes begun per S; held-elsewhere reports (durable, kept while the entry
//! is). Settle tells the engine of complete passes and own commits held elsewhere. Depends on
//! opens, streams, read, engine. Not built: every call below.

use crate::opens::Opens;
use crate::streams::Streams;
use crate::types::{Cx, Result, Scope, Waiting};
use osis_base::WallMs;
use std::sync::Arc;

/// Status now, per S: sources and their state, passes waiting; idle (spec/sync-status.md §3).
/// A memo value; its fields are the status owner's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StatusView {
    /// No request, fill or Hello outstanding on any connection.
    pub idle: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Status {}

impl Status {
    pub fn view(&mut self, cx: &mut Cx) -> Arc<StatusView> {
        let _ = cx;
        Arc::new(StatusView::default())
    }

    pub fn wait(&mut self, cx: &mut Cx, scope: Scope) -> Waiting {
        let _ = (cx, scope);
        Waiting::Never("status::wait not built")
    }

    /// Whether anything acted.
    pub fn settle(&mut self, cx: &mut Cx, opens: &Opens, streams: &Streams) -> Result<bool> {
        let _ = (cx, opens, streams);
        Ok(false)
    }

    pub fn next_wake(&self) -> Option<WallMs> {
        None
    }
}
