# trth-cli

TruthLinked CLI.

## Build

This repo expects the core chain repo to be checked out alongside it:

```
../truthlinked
../trth-cli
```

Then:

```
cargo build --release
```

## SDK Template

`sdk-new` uses the embedded template in `sdk/templates/rust-cell`.

## Notes

- The `truthlinked` dependency currently points to `../truthlinked` until the core repo is published.
