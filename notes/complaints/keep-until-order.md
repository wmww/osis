# keep-until-order
> Summary: Workflow notes from fixing the keep/until delivery-order seeds.

- The any-order keep properties print only the final kept sets; finding the cause took temporary `eprintln!`s of the op history and the kept set after each delivery. A history dump on failure would save the step.
