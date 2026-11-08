# stop_serving_erases_its_store fails under load
> Summary: `serving::stop_serving_erases_its_store_spec_data_model_9` (core/osis/tests/it/serving.rs:453) failed once in a full gate run with one label still listed after stopping (`left: [LabelId(..)]`, `right: []`), then passed alone 5 times and in the next gate. Likely a timing race between the stop and the host task ending.
> Priority: normal
> Tags: tests, serving

Reproduce by running the gate on a loaded box; not seen in a single-test run.
