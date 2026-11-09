# stop_serving_erases_its_store fails under load
> Summary: `serving::stop_serving_erases_its_store_spec_data_model_9` (core/osis/tests/it/serving.rs:453) failed in two full gate runs on a loaded box with one label still listed after stopping (`left: [LabelId(..)]`, `right: []`), each time passing alone 5 times. Likely a timing race between the stop and the host task ending.
> Priority: normal
> Tags: tests, serving

Reproduce by running the gate on a loaded box; not seen in a single-test run.
