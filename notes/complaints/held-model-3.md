# held-model-3
- A held-model mismatch in `arrival_order_purge_large` shrinks for 15+ minutes; `OSIS_ORDER_SHRINK=0` answers caught/missed in seconds.
- The order harness makes a node at the end time and sets its clock back: a check between early ingests sees the node's own commits ahead of its clock (the model parks them). The adapter now skips comparing `applied` for the node's own commits.
- Seed 3001 of the default `purge_large` range fails on main too (issues/order-seed-3001-purge-later-arrival.md): a red default range hides new failures there.
