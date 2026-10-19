//! Labeling (plans/node-sync.md): which blobs go under which label (closure, entitlement,
//! projection by retention class, retag), wraps, stamps and deposits, certificate blobs.
//! Local commits reach it as `Event::Applied { origin: Local, .. }`; node-core's deletion and
//! re-snapshot queues (`Engine::deletions`, the `resnapshot` log) are its inputs.
