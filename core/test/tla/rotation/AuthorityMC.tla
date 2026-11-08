------------------------------ MODULE AuthorityMC ------------------------------
(* Instance constants for Authority.tla (a .cfg cannot write tuples).        *)
EXTENDS Authority

\* 2-cycle: M holds a role on S, S on M
hold2 == {<<"S", "M">>, <<"M", "S">>}
\* 3-cycle: S holds M, T holds S, M holds T
hold3 == {<<"S", "M">>, <<"T", "S">>, <<"M", "T">>}
=============================================================================
