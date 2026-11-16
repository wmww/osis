# A node re-takes a revocation after following the thief's merge certificate
> Summary: roles-model `custody` (1 world in 8,000 random): B on X's side takes X's revocation #20 in its plain rotation #66, then follows X's certificate merging {2} and {16} (a line beside #66), whose line does not carry #20, and takes #20 again in #97: `bounded` (one event carried twice).
> Priority: normal
> Tags: engine, keys

- `cargo run --bin roles-model -- 8000 custody`; the failing world is printed (lockstep, b_switch 1, removal 5). Whether the engine does the same is not checked.
- The policy owes a plain rotation for a taken revocation its preferred line does not carry while it cannot merge; following a head that leaves its own carrying rotation behind makes the owed take recur. Either the preferred head should never leave a line carrying a taken revocation for one that does not, or "owed" should read the node's own held rotations.
