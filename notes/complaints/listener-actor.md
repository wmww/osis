# listener-actor
> Summary: footguns met fixing listeners to read as their subscriber.

- The tool-result of a failing test that prints `Debug` of `Value`s (keys.0 bytes) overflowed the output; cut long lines (`cut -c1-200`) before reading such failures.
