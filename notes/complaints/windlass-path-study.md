# windlass-path-study
> Summary: Complaints from the path-study task (roles-model `paths` variant, design notes).

- `tools/heavy cargo run --bin roles-model -- 200000 paths-whole` queued for over ten minutes behind another agent's single-core shrink (`roles-model 0 vouches-exh-state`, 106% CPU for half an hour under the all-core lock); stopped unrun. The short lane caps a `paths` search near 20,000 worlds (50,000 was stopped at 124 CPU-s), and the random search takes no start index, so a larger sample cannot be split across short runs.
