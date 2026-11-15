# A switched-back node is never handed its old side's head seed
> Summary: Custody lets a node of P that sided with the thief switch back (honest boxes open whatever counts), but a head a node made while on X's side boxes no device X revoked, and nothing re-seals that seed, so those devices cannot merge the heads: the switching-back differential settles with two heads at T in about 5% of worlds.
> Priority: critical
> Tags: security, engine

- Test: engine `rotation::tests_forks::engine_agrees_with_forks_model_switching_back_*` (ignored, naming this issue; 189 of 200 seeds pass).
- Shape: B takes X's revocation of T, rotates (boxing A, B, not T), its user switches back; B's rotation is a head at T, which holds no seed of it, so T cannot merge it with A's line, and A or B (holding both seeds) owe nothing that boxes T.
- Fix (notes/account-forks-design.md, Custody): a seed re-seal: any node holding a seed boxes it to a roster device it sees without one (the model's honest policy re-seals its heads' tip seeds). Needs a carrier for seed boxes outside a rotation (an account role commit's header field), deciding at the end of a complete pass.
