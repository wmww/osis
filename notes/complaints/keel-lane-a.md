# keel-lane-a
- A `StaticSchema` whose text fails to parse (a removed type name in a test fixture, e.g. `set<tid>`) surfaces only at run time as "t:reg.0 is not declared by its schema" on every aspect of that schema, hundreds of failures far from the cause. A parse failure of a static schema should panic naming the file and line.
- Retyping a field used across the engine (`BoxKey::holder` to `Weak`) is hundreds of compile errors; a small script applying `.0`/`Weak(..)` at rustc's JSON spans did most of them.
