# Held ephemeral history holds no targets
> Summary: Tess's rule (references in held history follow one rule, fires included) counts a strong in any held body under `history_holds_targets`; spec/data-model.md §8 Held history and the engine (`refs::kept::counted`) count durable aspects only, though an ephemeral aspect's current value counts while held. Either count held ephemeral bodies (memory rows, as their bodies are; their settle runs in memory transactions that skip `units::settle`) or give the model's reason.
> Priority: low
> Tags: engine, data-model
