# delete-reads
> Summary: slow spots and wrong turns met tracing a kept text edit's reads.

- `Io` (`measured`'s `w.io.reads`) counts debug-only checks: the issue as filed read the debug check `whole_date` as engine cost. The `store rows read` and `store blob bytes read` spans are the release counts.
- Finding who reads a blob: an `eprintln!` of `std::backtrace::Backtrace::force_capture()` in `Store::read_blob`, gated on `costs::on()` and the blob's size, names every frame in a debug test build (enough here; no gdb on ostrich).
- `scale::text_edits_are_flat` ran in about 4 minutes here; a 100k-char probe of `text_ops` alone takes about a minute.
