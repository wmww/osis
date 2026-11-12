# Content under a withdrawn epoch stays with its box holders
> Summary: An epoch whose names every holder of its secret finds unmet (refuted later: a named removal by an admin demoted concurrently) is withdrawn by a rotation that lists it, but its secret goes in no history box (established nowhere), so a holder its rotator left out never reads what the maker encrypted under it while it was established there.
> Priority: low
> Tags: keys, rotation

- Shape: `rotation::tests::unmet_epoch_withdrawn_by_its_maker_spec_crypto_4`. R rotates read naming a2's removal of M (e_R boxes no M) and may write under e_R; at every node holding D (a2's demotion, ordered before) the removal applies nothing, M reads on, e_R is unestablished wherever its secret is held, and R withdraws it. M, entitled all along, never gets e_R's secret: R's content in that window is unread by M.
- History boxes carry established secrets only (notes/crypto.md, R9: a node lacking a departure must not hand the epoch to the departed holder). Here every holder holds the refuting commits, so the refusal costs readability, not safety; a rule carrying a refuted epoch's secret must tell "refuted" from "named commit in flight", which nothing distinguishes now.
- Not checked by the rotation property: it compares only established epochs' secrets.
