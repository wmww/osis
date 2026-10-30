# eph-inflight-3300065
> Summary: complaints from fixing random_window_inflight seed 3300065.

- The failure dump showed the lane but not the connection's label phase; the cause (label `Failed` at one server after REFUSED opens) only showed once `describe()` went into `lane_dump`. `lane_dump` prints it now.
- Ad hoc env vars for debug prints panic (`testenv::KNOWN`); reuse `OSIS_TEST_DIAG` for throwaway prints.
