# Start fresh offered for errors that are not the store's
> Summary: The startup error screen (libs/kit/src/render/start.rs) offers Start fresh for any startup failure, including the app's data setup (desktop `--demo`, `--theme`) and `Ui::new`, which would move a healthy store aside; offer it only when opening the store itself failed. Also: a store opened before a later step fails is dropped without `close`, staying locked briefly.
> Priority: low
> Tags: app
