# A text session's commit blocks typing into it
> Summary: The idle-commit timer (and the remote-merge handler) hold the session's lock across `flush`, which waits for the node lock and commits. A keystroke on the UI thread (`TextSession::splice`, `text`) waits on that session lock, so typing stalls for as long as the node is busy elsewhere (a sync apply, a render's reads) plus the commit.
> Priority: normal
> Tags: osis, kit, app

- Path: `osis::text::arm`'s timer locks `State`, then `flush` → `db.write().commit()` (node lock). Kit's `Sessions::typed` → `edit::splice` → `s.text()` and `s.splice()` lock the same `State` on the UI thread. The `on_change` merge handler does the same as the timer. `edit` also flushes on the UI thread itself when the pause passed without the timer firing.
- Not a one-line fix: committing outside the lock needs an in-flight state, since two flushes from one `base` (timer and merge handler) would apply the same `Op::Edit` twice. Shape to look at: snapshot `(base, buf)` under the lock, commit unlocked with at most one flush in flight per session, then `base = snapshot` under the lock.
- Same class, bigger: kit renders on the UI thread and every osis read there takes the node lock, so the UI already waits on a busy node during a re-render. Decide both together (what the UI thread may wait on).
