# trth-cli

```bash
$ trth-cli --rpc https://rpc.truthlinked.org chain-info
{
  "height": 1,
  "finalized_height": 0,
  "genesis_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "chain_id": "0000000000000000000000000000000000000000000000000000000000000000",
  "foundation_mint_authority": "c537050abe15a89a133b46e969cd61fb8fdec9b786ffdac462ffe27b3df0e7c9"
}
```


A command line client for TruthLinked. It handles local keys, builds and signs transactions, talks to the RPC, and includes the SDK workflow for building and deploying cells.

## Build

This repository currently expects the core chain repository to be checked out next to it.

```
../truthlinked
../trth-cli
```

Build the CLI:

```bash
cargo build --release
```

Run it:

```bash
./target/release/trth-cli --help
```

## Configuration

The CLI reads two global flags that apply to every command.

1. `--rpc` sets the RPC base URL. The default is `https://rpc.truthlinked.org`.
2. `--output` controls formatting. Use `pretty` for humans and `json` for automation.

Example:

```bash
trth-cli --rpc https://api.truthlinked.org --output json chain-info
```

## Keys and accounts

Account IDs are derived locally from the Dilithium public key. Keyfiles are stored on disk and can be encrypted. The CLI can also generate a new mnemonic and keyfile without any RPC calls.

Create a new account and keyfile:

```bash
trth-cli account-create --encrypt
```

Import from a BIP39 mnemonic:

```bash
trth-cli import-mnemonic --mnemonic "..." --output ~/.truthlinked/default.keys
```

Get the account id from a keyfile:

```bash
trth-cli account-id --from ~/.truthlinked/default.keys
```

## Common operations

Check chain and network state:

```bash
trth-cli chain-info
trth-cli token-info
trth-cli network-info
```

Balances:

```bash
trth-cli balance --account-id <account_id>
trth-cli balance-by-pubkey --pubkey <pubkey_hex>
```

Transfers:

```bash
trth-cli transfer --from keys.json --to-pubkey <pubkey_hex> --amount 5
trth-cli purchase-cu --from keys.json --trth-amount 1
```

Airdrop on testnet:

```bash
trth-cli airdrop --from keys.json --amount 50
```

## Cells and SDK

Create a new SDK project and build it for the `truthlinked-cells` target:

```bash
trth-cli sdk-new --path ./my-cell
trth-cli sdk-build --path ./my-cell
```

Deploy a cell built from the SDK:

```bash
trth-cli sdk-deploy --from keys.json --cell-id <cell_id_hex> --path ./my-cell
```

You can also deploy or upgrade from a single source file or a compiled wasm.

```bash
trth-cli deploy-cell --from keys.json --cell-id <cell_id_hex> --source ./src/lib.rs
trth-cli upgrade-cell --from keys.json --cell-id <cell_id_hex> --bytecode-file ./cell.wasm
```

## Governance and system cells

The CLI includes commands for treasury proposals, system cell proposals, token authority governance, and URL oracle governance. Use `--help` on any command to see the full flags.

## Notes

The `truthlinked-core` dependency currently points to `../truthlinked/crates/truthlinked-core` until the core repo is published. It will be switched to a git dependency when the main repo is public.
