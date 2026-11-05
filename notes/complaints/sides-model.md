# sides-model complaints
> Summary: TLC runs in parallel share java.io.tmpdir and race on extracting the standard modules.

- Several TLC JVMs started at once failed parsing at random ("Module-Table lookup failure", a null `str`): each extracts Naturals/FiniteSets into `/tmp`. `-Djava.io.tmpdir=<per-run dir>` fixes it (sides/matrix.sh does). run.sh is sequential, so unaffected.
- Many small TLC runs cost JVM startup (2-3 s each at load 30): 330 runs took 13 min for at most 78k states each.
