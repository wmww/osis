# signing-model
- `roles-model -- 0 epochs-exh` ran single-threaded (7.7 min for 939k worlds); it now shards over every core (both families 47 s).
- The epochs model's removed node signed only at epoch 0 or its own forks, never at a sibling's concurrently minted epoch, which hid the account-signing hole: when a model abstracts what an attacker holds, check it against every key the honest side may box it.
