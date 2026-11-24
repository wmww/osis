# A prune-only skip in `Effects::due` saves the key's stamp in a second step
> Summary: osis-base memo: when `due` skips a reader whose read moved only by a prune, it checks the key's stamp and then saves it in a separate step; a write to that key from another thread between the two would be missed. Latent: nothing writes a followed table from another thread during `due` (all behind the engine). Make the check-and-save one step if cheap, or when a second writer thread appears.
> Priority: low
> Tags: base, memo

The single-thread cases are covered (`a_prune_hides_no_write_beside_it`).
