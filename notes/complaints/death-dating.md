# death-dating
- An engine-only rebuild (`cargo build -p osis-engine`) took 4 min at load 40; the node test binary another 4-5 min per iteration. Instrumenting (an env-gated `eprintln!`) cost two such rounds; the first round printed nothing because the path I suspected (the replay) never ran: the dates came from the incremental path. Print at both before suspecting one.
