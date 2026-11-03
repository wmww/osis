# purge-seeds
> Summary: Footguns met fixing the purge order seeds.

- `eprintln!` from inside `alike` never showed in a failing oracle's captured output (dump_orders' did); writing a probe to a scratch file worked. Unclear why; cost a few reruns.
- Any new env var must be listed in core/base/testenv-known.txt or the test binary refuses to start; reuse `OSIS_ORDER_DUMP` for throwaway probes.
- Tier 1 took 10 min under load 30 (warm, 40 s idle): the engine change rebuilt every dependent crate's tests.
- Review: the gate took 684 s at load 27 (about a minute quiet); the per-branch order set at one offset took 12 min wall at that load.
