# A rotation through an unproven holder actor stands when a demotion's frontier saves it

> Summary: possession lets a rotation of M through holder actor A that shows no proof for A count where the author held the role at its key only by §5.2 (a later demotion's frontier, a re-grant): possession then defers to §5.2, which never asks for a proof. Its leak (the maker reads M's epoch after leaving A) is closed by the maker departure rule; what is left is a rotation every honest writer would refuse. Found by `rotation_holds` seed 3141590091.
> Priority: low
> Tags: security, engine, keys

## Shape
A {P, ...} holds write on M (here keylessly, M and A in a cycle, so M boxes A nothing). The admin
demotes P to read on A. P, unaware, rotates M; at its key P holds only read on M, so
`osis_keys::possession::holds` takes the "author holds no such role" branch and leaves the verdict
to §5.2. The admin re-grants P write on A, then removes P: that removal's frontier lists P's
rotation, so §5.2 makes it valid. No proof for A was ever shown, yet the rotation stands. An honest
writer never makes it (`members::authority` refuses a rotation through A without a proof for A);
only a writer past its own rules does.

## What closes the leak (built)
The maker of a current epoch holds its secret whatever the boxes say. One holding less than that
role now, for keys and by any path (`Timeline::role` at `At::KEYS`), departed the actor, attributed
to nothing (`rotation::departures::direct_departures`; spec/crypto.md §4 Departure). So M's epoch
P made is uncovered once P leaves A, the admin rotates M before sealing it into A, and P opens
nothing new (`tests_members::maker_lowered_through_a_holder_actor_opens_nothing_new_spec_crypto_4`).
This holds however a rotation came to be valid, so the possession gap no longer leaks.

## Left
Whether possession should also judge a rotation saved by a frontier or a re-grant, by the path its
author held the role on before the demotion. Not needed for the read property; low.

