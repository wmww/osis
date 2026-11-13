# test-profile-5
- `tools/cpuprof --report` symbolizes the whole sample file again per call (a few minutes for a whole-binary profile); querying many filters meant writing a throwaway script that symbolizes once and pickles. A `--report` mode taking several filters, or a cached symbol table next to the samples, would save that.
- Sample shares and instruction savings disagree a lot: the debug `first_held` replay was 3.7% of node `it`'s samples but removing its repeats saved 1.5% of instructions. Counting what a change saves needs a build and `tools/icount`, not the profile.
- A first forensic-memo build saved nothing: the probe counted repeated (section, candidate) pairs but not that almost every expensive section ends opened. Probe the outcome distribution before building.
