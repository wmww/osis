# purge-by
- A line filter dropping `retention::`/`retention/` path hits (to skip the engine module) also dropped every line of files under `retention/` (the path is in rg's `file:` prefix): five "purgeable-by" comments in core/engine/src/retention/ survived the first sweep. Filter on the text after the line number, not the whole rg line.
- "retention" names four things (a write's purge-by, the thing's setting `retention^.0`, the engine module, the fixed-retention aspect class); about 1700 hits had to be read one by one.
- The codegen pin in schema `evolution::value_form_and_codegen_bytes_pinned_spec_data_model_10` hashes example.osis's source text, so a DSL keyword rename moves it with no change to the value form.
