# app-review3
> Summary: Mishaps met while reviewing the app prototype's milestone 4 work.

- The time tests ran in the machine's zone (UTC here), so a DST bug in `span` passed a test meant to catch it; zone-taking `*_in` variants now exist for tests.
- The review was killed mid-step for a benchmark run; the background build had to be restarted.
