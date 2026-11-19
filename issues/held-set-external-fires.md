# held_set_decides generates no external fire
> Summary: osis-engine `tests/it/held.rs` passes `ExternalFires::Enabled`, but the order harness never produces a fire by a party holding no write, so the engine is never compared with held-model on the external-fire rule.
> Priority: normal
> Tags: tests, engine

- held-model's external worlds (`held_model::external`, `props_external.rs`) run against the model alone; engine rule tests are `tests/it/external.rs`.
- Not a generator tweak: the harness's three playing peers all hold write on G (0 admin, 1 write, 2 admin), and the re-grant rule makes a fire by any peer that ends as a writer valid by its authority. A stranger's fire needs a playing peer holding no write on G for the whole history (a fourth playing peer, or an emphasis whose start lowers peer 1 to read for good), plus steps for an enabling and a disabling setting and a fire past the writer's check; or run held-model's external worlds through the engine adapter.
