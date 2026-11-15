# fathom-test-opt-16
- `tools/cpuprof --report` has no caller view: who calls a hot function (the frame above its outermost match) took a scratch script. Worth a `--callers FN` mode.
- A process-wide count (`memo::writes`) is moved by every test thread: a counting test of it needs a child process with one test thread (`facade::queries_between_writes_follow_once`), and its saving in a parallel binary is about half a lone world's.
