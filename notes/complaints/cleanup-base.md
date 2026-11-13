# cleanup-base
- `pub(crate)` probe on a crate whose lib.rs re-exports (`pub use`): rustc errors on private re-exports and reports no dead code until the `pub use` lines become `pub(crate) use` too; then every item reads unused at once (nothing in osis-base uses its own API), so the probe only yields a candidate list to grep. A per-name grep of the workspace was the useful pass.
- osis-base is already lean: the probe and dead_pub found nothing dead; the volume was the decoder's duplicated head rules (check vs decode).
