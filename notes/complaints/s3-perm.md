# s3-perm
> Summary: Workflow snags met building vouches in osis-perm.

- `tools/mutate.py` plants each OLD as an expression: an OLD that is the tail of a `&&` chain (`&& f(x)`) or a method path without its call does not build, and one such site failed the whole first batch. Pick whole operands.
- `roles-model -- 1000000 vouches-state` takes about 120 CPU-s in the dev profile: just over `tools/heavy --short`'s cap, so it needs the full lock (and waited minutes behind another hold).
- The core aspect role-class lists live in four places (`core_types::ROLE_CLASS`, `osis_keys::UNDER_ROLES`, engine `forget::KEPT`, the never-compacted check); only the first is derived from the schema.
