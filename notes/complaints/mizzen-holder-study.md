# Complaints: mizzen-holder-study
> Summary: Slow spots met in the holder-access design study.

- spec/crypto.md §4 and spec/permissions.md §3 have bullets of over a kilobyte each: a tool read of one section overflows its output limit and has to be paged by line range.
- Nothing prints the bytes of a role change through a holder (a removal's rotation by roster size, the rotation it forces below): `thing_cost` covers one grant. The study packaged the commits by hand in a throwaway test; a row in `thing_cost::what_a_reader_costs` would have saved it (issues/holder-key-churn.md, Measured).
