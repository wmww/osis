# A holder of a thing's genesis seed can squat a store standing at its genesis step
> Summary: A store keeping S unread whose path is the genesis step alone takes any child its delete key signs; that key derives from the genesis seed, which a party removed from the thing's mint admin chain may hold, so such a party registering a child first leaves the store refusing the real first step (an equal-depth sibling). Proposed fix: a store prefers a branch bearing a sync key it holds itself.
> Priority: low
> Tags: security, sync

Shown by `store::a_genesis_seed_holder_squats_a_store_at_genesis_spec_sync_hostile_2` (osis-sync): the fake child is taken (0), the real one refused (9). spec/sync-hostile.md §2 states it as what such a party can do. Window: every new store, between taking the genesis step (a source holding no step takes it at once, `inbox::register`) and the first step's registration, and any empty store a squatter reaches first with `[genesis, fake]`.

What it costs the thing: that store is blocked for S for good. A real branch leaves the path at the genesis step, whose delete key is not the fake head's, so the store takes it only with an endorsement by the fake's delete key, which only the squatter holds. The squatter gains no read (it holds no read secret); the store takes its stamps and deposits and none of the thing's.

Fix proposed (not built: it reaches into the store's judgement, which decrypts nothing and holds no secret today): a store that holds a sync secret of S (every store keeping S unread does, by its grant) takes, over its head, a branch whose last step bears a sync key one of its secrets derives while its head bears none, whatever the depths. A squatter cannot forge such a step without the sync secret; a removed sync holder bearing an older key gains nothing (its key is in the real path below the head). Check against the hostile relay rules in `store::path::register` (no flip between real siblings: both bear held keys, so depth still decides).
