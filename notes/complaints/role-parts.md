# role-parts
> Summary: workflow notes from the role-parts read-time fix.

- A main-vs-branch probe (checking out five engine files from main into a probe commit) rebuilt the engine lib test binary for over two minutes: the check that the end-to-end test fails on main costs a full engine rebuild each way.
- On main the end-to-end test fails at the drop-time judgment check ("opened from the persisted index: judged anew"), before the test's own restart assertion: the debug check is what shows the symptom.
