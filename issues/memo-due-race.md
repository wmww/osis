# A prune-only skip in `Effects::due` saves the key's stamp in a second step
> Summary: osis-base memo: when `due` skips a reader whose read moved only by a prune (232f3dd96), it checks the key's stamp and then saves it in a separate step; a write to that key from another thread between the two would be missed. Nothing writes a followed table from another thread during `due` today (all behind the engine), so it is latent. Fix when a second writer thread appears, or make the check-and-save one step now if it is cheap.
> Priority: low
> Tags: base, memo

Found by the review of read-rejudge; the review's test `a_prune_hides_no_write_beside_it` covers the single-thread cases.
