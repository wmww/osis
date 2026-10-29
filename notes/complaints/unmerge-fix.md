# unmerge-fix
- The debug check "in-place un-merge differs from a rebuild" fires at the first in-place un-merge after the real divergence, which here happened at an earlier snapshot join (no check there). A temporary probe comparing every state with `rebuilt` after each `apply_verified` found the commit in one run; worth keeping in mind before reading the un-merge code.
- Merging `Owned::Dots` groups per source left `ctrs` unsorted (the type's doc says sorted; `owns` binary-searches): validity broke silently and showed only as the same debug assertion across the alike harness. Read the type before reshaping its values.
- Started a second background scan while the first still ran (wrote the same log names); check `claudewait` reported the first one finished before reusing log paths.
