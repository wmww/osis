# s3-spec complaints
> Summary: Workflow notes from the S3 vouches and addenda-gaps spec task.

- schema/core.osis is normative for core aspect types but is compiled by core/osis/build.rs, so a spec-only branch cannot add `vouches.0` there without leaving the docs-only gate path: the type is stated in spec/data-model.md §9 and the declaration is the build's first piece (issues/s3-vouches-build.md).
- `tools/policy.py --baseline` passed while two test anchors citing §5.2 Addenda text broke; only the gate's `spec_map.py --uncited --gaps` caught it. Run `python3 tools/spec_map.py --uncited --gaps` after editing cited spec text.
