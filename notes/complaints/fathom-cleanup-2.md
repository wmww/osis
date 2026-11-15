# fathom-cleanup-2
- The `#[deprecated]` probe's warnings name items by the path the caller used (`osis::internals::osis_engine::...`, `module::Type::f` inside the crate), so aggregating by item needs a last-segment match; an `<impl X>` path holds a space. A shared script in tools/ would save each cleanup round rewriting it.
- Several allow-list entries (`dead_pub_allow.txt`) named callers that had gone (`carried_dots` "test hook", `destructions` "facade"): an allow reason is never rechecked by policy.
