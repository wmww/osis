# review-path-wake
> Summary: footguns met reviewing the path-wake fix (engine-it-tests-3).

- A differential of a fix that also changed a copy (`Core::test_copy` cloning the wait) must keep that change while reverting the rest, or the copy gap fails the test first and hides whether the rollback case is covered.
