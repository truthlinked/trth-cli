//! TruthLinked CLI: local key management + rpc client + transaction builder.
//!
//! This file holds both the command definitions and the rpc/tx helpers
//! to keep the CLI as a single self-contained binary.
use clap::{Parser, Subcommand, ValueEnum};
use include_dir::{include_dir, Dir};
use bip39::Mnemonic;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use truthlinked::*;
use fips204::traits::{SerDes, Signer};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;

/// Resolve the default keyfile path (`~/.truthlinked/default.keys`).
/// Falls back to `default.keys` if the home directory is unavailable.
fn default_keyfile_path() -> String {
    dirs::home_dir()
        .map(|p| p.join(".truthlinked").join("default.keys"))
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "default.keys".to_string())
}

static SDK_TEMPLATE_DIR: Dir = include_dir!(
    "$CARGO_MANIFEST_DIR/../sdk/templates/rust-cell"
);

#[derive(Deserialize)]
#[allow(dead_code)]
struct RpcAccountInfo {
    account_id: String,
    found: bool,
    balance: String,
    balance_trth: String,
    is_cell: bool,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RpcCellInfo {
    cell_id: String,
    found: bool,
    is_token: bool,
    immutable: bool,
}

/// Top-level CLI arguments.
///
/// `rpc` points to the TruthLinked rpc base url.
/// `output` controls pretty vs json rendering for automation.
#[derive(Parser)]
#[command(name = "trth-cli")]
#[command(about = "TruthLinked CLI tool")]
struct Cli {
    /// rpc base url, e.g. `https://rpc.truthlinked.org`
    #[arg(long, default_value = "https://rpc.truthlinked.org")]
    rpc: String,

    /// Output format for all commands (`pretty` or `json`)
    #[arg(long, default_value = "pretty", value_enum)]
    output: OutputFormat,
    
    #[command(subcommand)]
    command: Commands,
}

/// Output format for machine vs human consumption.
#[derive(ValueEnum, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Pretty,
    Json,
}

/// Treasury buckets available for governance spend proposals.
#[derive(ValueEnum, Clone, Copy)]
enum TreasuryBucket {
    Community,
    Treasury,
    Validators,
    Strategic,
}

/// CLI command surface.
///
/// Read-only commands map 1:1 to rpc endpoints and return the raw json response
/// (or a pretty-printed version of it).
///
/// Transaction commands build a `Transaction` locally, sign it with the provided
/// key file, then submit via `post /submit_raw` with raw bytes.
///
/// ---------------------------------------------------------------------------
/// Rpc response schemas (json schema + example)
/// ---------------------------------------------------------------------------
/// These schemas describe the exact fields the CLI expects to parse.
/// They are strict for tooling and automation.
///
/// 1) get /chain_info
/// Schema:
/// {
///   "type":"object",
///   "required":["height","finalized_height","genesis_hash","chain_id"],
///   "properties":{
///     "height":{"type":"integer"},
///     "finalized_height":{"type":"integer"},
///     "genesis_hash":{"type":"string","description":"32-byte hex"},
///     "chain_id":{"type":"string","description":"32-byte hex"},
///     "foundation_mint_authority":{"type":["string","null"],"description":"account id hex"}
///   }
/// }
/// Example:
/// {
///   "height":6214,
///   "finalized_height":6208,
///   "genesis_hash":"ab…32",
///   "chain_id":"ab…32",
///   "foundation_mint_authority":"9f…8c"
/// }
///
/// 2) get /token_info
/// Schema:
/// {
///   "type":"object",
///   "required":["name","symbol","total_supply","decimals","subunit"],
///   "properties":{
///     "name":{"type":"string"},
///     "symbol":{"type":"string"},
///     "total_supply":{"type":"string","description":"formatted amount"},
///     "decimals":{"type":"integer"},
///     "subunit":{"type":"string"}
///   }
/// }
/// Example:
/// {"name":"TruthLinked","symbol":"trth","total_supply":"1000000000 trth","decimals":9,"subunit":"dilith"}
///
/// 3) get /network_info
/// Schema:
/// {
///   "type":"object",
///   "required":["discovered_peers","connected_peers","syncing"],
///   "properties":{
///     "discovered_peers":{"type":"integer"},
///     "connected_peers":{"type":"integer"},
///     "syncing":{"type":"boolean"}
///   }
/// }
/// Example: {"discovered_peers":12,"connected_peers":3,"syncing":false}
///
/// 4) get /validators
/// Schema (array of validators):
/// {
///   "type":"array",
///   "items":{
///     "type":"object",
///     "required":["pubkey","active_stake","jailed","commission_bps"],
///     "properties":{
///       "pubkey":{"type":"string","description":"hex public key"},
///       "active_stake":{"type":"string","description":"raw units"},
///       "jailed":{"type":"boolean"},
///       "commission_bps":{"type":"integer"},
///       "delegates":{"type":"array","items":{"type":"string"}}
///     }
///   }
/// }
/// Example: [{"pubkey":"aa…","active_stake":"5000000000","jailed":false,"commission_bps":500,"delegates":[]}]
///
/// 5) get /mempool
/// Schema:
/// {
///   "type":"object",
///   "required":["size","transactions"],
///   "properties":{
///     "size":{"type":"integer"},
///     "transactions":{"type":"array","items":{"type":"object"}}
///   }
/// }
/// Example: {"size":2,"transactions":[{"hash":"…"}]}
///
/// 6) get /resolve/{query}
/// Schema:
/// {
///   "type":"object",
///   "properties":{
///     "kind":{"type":"string"},
///     "id":{"type":"string"},
///     "data":{"type":"object"}
///   }
/// }
/// Example: {"kind":"tx","id":"…","data":{"status":"confirmed"}}
///
/// 7) get /cell_proposals
/// Schema:
/// {
///   "type":"array",
///   "items":{
///     "type":"object",
///     "properties":{
///       "cell_id":{"type":"string"},
///       "proposal_type":{"type":"string"},
///       "votes_for":{"type":"integer"},
///       "votes_against":{"type":"integer"},
///       "timelock_blocks":{"type":"integer"},
///       "executed":{"type":"boolean"}
///     }
///   }
/// }
///
/// 8) get /tx/{hash}
/// Schema:
/// {
///   "type":"object",
///   "properties":{
///     "status":{"type":"string"},
///     "hash":{"type":"string"},
///     "block_height":{"type":["integer","null"]},
///     "error":{"type":["string","null"]}
///   }
/// }
/// Example: {"status":"confirmed","hash":"…","block_height":6209}
///
/// 9) post /balance
/// Request body:
/// {"account_id":"<32-byte-hex>"}
/// Response schema:
/// {
///   "type":"object",
///   "required":["account_id","balance","balance_trth","is_cell"],
///   "properties":{
///     "account_id":{"type":"string"},
///     "balance":{"type":"string","description":"raw units"},
///     "balance_trth":{"type":"string","description":"formatted"},
///     "is_cell":{"type":"boolean"}
///   }
/// }
///
/// 10) post /balance_by_pubkey
/// Request body:
/// {"pubkey":"<hex pubkey>"}
/// Response schema: same as /balance plus derived account_id.
///
/// 11) post /submit_raw
/// Request body: raw bytes (postcard-encoded Transaction)
/// Response schema:
/// {
///   "type":"object",
///   "required":["success"],
///   "properties":{
///     "success":{"type":"boolean"},
///     "hash":{"type":["string","null"]},
///     "error":{"type":["string","null"]}
///   }
/// }
/// Example: {"success":true,"hash":"…"}
///
/// ---------------------------------------------------------------------------
#[derive(Subcommand)]
enum Commands {
    /// Get chain info.
    ///
    /// Request: GET `/chain_info`
    /// Response: `{ height, finalized_height, genesis_hash, chain_id, foundation_mint_authority }`
    ChainInfo,
    /// Get token info.
    ///
    /// Request: GET `/token_info`
    /// Response: `{ name, symbol, total_supply, decimals, subunit }`
    TokenInfo,
    /// Get network info.
    ///
    /// Request: GET `/network_info`
    /// Response: `{ discovered_peers, connected_peers, syncing }`
    NetworkInfo,
    /// Get validators list.
    ///
    /// Request: GET `/validators`
    /// Response: array of validator records (pubkey, stake, status, jailed, etc).
    Validators,
    /// Get mempool info.
    ///
    /// Request: GET `/mempool`
    /// Response: `{ size, transactions: [...] }` (exact shape defined by rpc).
    Mempool,
    /// Resolve any hash/id/name using the universal indexer.
    ///
    /// Request: GET `/resolve/{query}`
    /// Response: indexer record describing the resolved resource (tx, cell, account, name, etc).
    Resolve { query: String },
    /// List active cell governance proposals.
    ///
    /// Request: GET `/cell_proposals`
    /// Response: list of proposals with status, votes, and timelocks.
    ListCellProposals,
    /// Get transaction status by hash.
    ///
    /// Request: GET `/tx/{hash}`; if not found, fallback GET `/mempool/tx/{hash}`
    /// Response: `{ status, hash, ... }` (confirmed/pending/not_found).
    TxStatus { hash: String },
    /// Get balance by account ID (hex).
    ///
    /// Request: post `/balance` `{ account_id }`
    /// Response: `{ account_id, balance, balance_trth, is_cell, ... }`
    Balance { account_id: String },
    /// Get balance by public key (hex).
    ///
    /// Request: post `/balance_by_pubkey` `{ pubkey }`
    /// Response: `{ account_id, balance, balance_trth, ... }`
    BalanceByPubkey { pubkey: String },
    /// Get account ID from keypair or public key (local derivation).
    ///
    /// No rpc calls. Derives account ID as SHA256("truthlinked-account-id-v1" || pubkey).
    AccountId {
        /// Path to keyfile (optional if --pubkey provided)
        #[arg(long)]
        from: Option<String>,
        /// Public key hex (optional if --from provided)
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Import keypair from mnemonic (local only).
    ///
    /// No rpc calls. Writes a keyfile that can be used for signing.
    ImportMnemonic {
        /// BIP39 mnemonic phrase
        #[arg(long)]
        mnemonic: String,
        /// Output keyfile path (default: ~/.truthlinked/default.keys)
        #[arg(long, default_value_t = default_keyfile_path())]
        output: String,
        /// Optional passphrase
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Create a new keypair and mnemonic (local only).
    ///
    /// No rpc calls. Writes a keyfile and prints a mnemonic for backup.
    AccountCreate {
        /// Output keyfile path (default: ~/.truthlinked/default.keys)
        #[arg(long, default_value_t = default_keyfile_path())]
        output: String,
        /// Encrypt keyfile with a password (recommended)
        #[arg(long)]
        encrypt: bool,
        /// Optional mnemonic passphrase (for recovery)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Claim testnet airdrop (50 trth max, 12hr cooldown).
    ///
    /// Request: post `{airdrop_url}/airdrop` with signed request body.
    /// Response: `{ success, error? }`
    Airdrop {
        /// Path to keys file
        #[arg(long)]
        from: String,
        /// Amount in trth (max 50)
        #[arg(long, default_value = "50")]
        amount: u64,
    },
    /// Propose a treasury spend (governance + timelock).
    ///
    /// Builds a governance transaction and submits via `post /submit_raw`.
    TreasuryProposeSpend {
        /// Path to proposer keys file
        #[arg(long)]
        from: String,
        /// Bucket to spend from
        #[arg(long, value_enum)]
        bucket: TreasuryBucket,
        /// Recipient account id (hex)
        #[arg(long)]
        recipient: String,
        /// Amount in trth
        #[arg(long)]
        amount: u64,
        /// Timelock in blocks
        #[arg(long)]
        timelock_blocks: u64,
        /// Optional proposal id (32-byte hex). If omitted, a random id is generated.
        #[arg(long)]
        proposal_id: Option<String>,
    },
    /// Vote on a treasury spend proposal.
    ///
    /// Builds a governance vote transaction and submits via `post /submit_raw`.
    TreasuryVoteSpend {
        /// Path to voter keys file
        #[arg(long)]
        from: String,
        /// Proposal id (32-byte hex)
        #[arg(long)]
        proposal_id: String,
        /// Approve proposal
        #[arg(long)]
        approve: bool,
    },
    /// Execute a treasury spend proposal.
    ///
    /// Builds an execution transaction and submits via `post /submit_raw`.
    TreasuryExecuteSpend {
        /// Path to executor keys file
        #[arg(long)]
        from: String,
        /// Proposal id (32-byte hex)
        #[arg(long)]
        proposal_id: String,
    },
    /// Fetch treasury proposal info.
    ///
    /// Request: GET `/treasury/proposal/{id}` (rpc path determined by server).
    TreasuryProposalInfo {
        /// Proposal id (32-byte hex)
        #[arg(long)]
        proposal_id: String,
    },
    /// Transfer trth.
    ///
    /// Builds a signed `Transfer` transaction and submits via `post /submit_raw`.
    Transfer {
        /// Path to sender keys file
        #[arg(long)]
        from: String,
        /// Recipient pubkey (hex)
        #[arg(long)]
        to_pubkey: String,
        /// Amount in trth
        #[arg(long)]
        amount: u64,
    },
    /// Purchase compute units (cu) using trth.
    ///
    /// Builds a signed `Purchasecu` transaction and submits via `post /submit_raw`.
    PurchaseCU {
        /// Path to sender keys file
        #[arg(long)]
        from: String,
        /// Amount in trth to convert
        #[arg(long)]
        trth_amount: u64,
    },
    /// Batch transfer to multiple recipients (comma-separated pubkeys and amounts).
    ///
    /// Builds a signed `BatchTransfer` transaction and submits via `post /submit_raw`.
    BatchTransfer {
        /// Path to sender keys file
        #[arg(long)]
        from: String,
        /// Comma-separated recipient pubkeys (hex)
        #[arg(long)]
        to_pubkeys: String,
        /// Comma-separated amounts in trth
        #[arg(long)]
        amounts: String,
    },
    /// Setup validator (register + bond in one command).
    ///
    /// Builds a signed `Stake` transaction and submits via `post /submit_raw`.
    ValidatorSetup {
        /// Path to validator keys file
        #[arg(long)]
        keys: String,
        #[arg(long)]
        amount: u64,
    },
    Bond {
        #[arg(long)]
        from: String,
        #[arg(long)]
        amount: u64,
    },
    /// Unbond stake (starts unbonding period).
    ///
    /// Builds a signed `Unstake` transaction and submits via `post /submit_raw`.
    Unbond {
        /// Path to validator keys file
        #[arg(long)]
        from: String,
        /// Amount in trth to unstake
        #[arg(long)]
        amount: u64,
    },
    /// Withdraw unbonded stake.
    ///
    /// Builds a signed `WithdrawStake` transaction and submits via `post /submit_raw`.
    Withdraw {
        /// Path to validator keys file
        #[arg(long)]
        from: String,
    },
    /// Unjail validator.
    ///
    /// Builds a signed `Unjail` transaction and submits via `post /submit_raw`.
    Unjail {
        /// Path to validator keys file
        #[arg(long)]
        from: String,
    },
/// Add a staking delegate (allows delegate to act on a validator).
    DelegateAdd {
        /// Path to owner keys file
        #[arg(long)]
        from: String,
        /// Delegate public key hex
        #[arg(long)]
        delegate_pubkey: String,
    },
    /// Remove a staking delegate
    DelegateRemove {
        /// Path to owner keys file
        #[arg(long)]
        from: String,
        /// Delegate public key hex
        #[arg(long)]
        delegate_pubkey: String,
    },
    /// Stake on behalf of a validator (delegate only)
    StakeFor {
        /// Path to delegate keys file
        #[arg(long)]
        from: String,
        /// Validator public key hex (owner)
        #[arg(long)]
        owner_pubkey: String,
        /// Amount in trth
        #[arg(long)]
        amount: u64,
    },
    /// Unstake on behalf of a validator (delegate only).
    ///
    /// Builds a signed `Unstake` transaction and submits via `post /submit_raw`.
    UnstakeFor {
        /// Path to delegate keys file
        #[arg(long)]
        from: String,
        /// Validator public key hex (owner)
        #[arg(long)]
        owner_pubkey: String,
        /// Amount in trth
        #[arg(long)]
        amount: u64,
    },
    /// Withdraw on behalf of a validator (delegate only).
    ///
    /// Builds a signed `WithdrawStake` transaction and submits via `post /submit_raw`.
    WithdrawFor {
        /// Path to delegate keys file
        #[arg(long)]
        from: String,
        /// Validator public key hex (owner)
        #[arg(long)]
        owner_pubkey: String,
    },
    /// Unjail on behalf of a validator (delegate only).
    ///
    /// Builds a signed `Unjail` transaction and submits via `post /submit_raw`.
    UnjailFor {
        /// Path to delegate keys file
        #[arg(long)]
        from: String,
        /// Validator public key hex (owner)
        #[arg(long)]
        owner_pubkey: String,
    },
    /// Lock trth into vetrth.
    ///
    /// Builds a `CallCell` into the vetrth system cell and submits via `post /submit_raw`.
    VetrthLock {
        #[arg(long)]
        from: String,
        /// Amount in trth to lock
        #[arg(long)]
        amount: u64,
        /// Lock duration in blocks
        #[arg(long)]
        lock_blocks: u64,
    },
    /// Extend an existing vetrth lock.
    ///
    /// Builds a `CallCell` into the vetrth system cell and submits via `post /submit_raw`.
    VetrthExtend {
        #[arg(long)]
        from: String,
        /// New lock duration in blocks (from now)
        #[arg(long)]
        lock_blocks: u64,
    },
    /// Unlock matured vetrth position.
    ///
    /// Builds a `CallCell` into the vetrth system cell and submits via `post /submit_raw`.
    VetrthUnlock {
        #[arg(long)]
        from: String,
    },
    
    // NFT commands
    /// Mint NFT.
    ///
    /// Builds a signed `MintNFT` transaction and submits via `post /submit_raw`.
    MintNft {
        #[arg(long)]
        from: String,
        #[arg(long)]
        nft_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        metadata_uri: String,
        #[arg(long)]
        collection: Option<String>,
        #[arg(long, default_value = "0")]
        royalty_bps: u16,
        #[arg(long)]
        royalty_recipient: Option<String>,
    },
    /// Transfer NFT.
    ///
    /// Builds a signed `TransferNFT` transaction and submits via `post /submit_raw`.
    TransferNft {
        #[arg(long)]
        from: String,
        #[arg(long)]
        nft_id: String,
        #[arg(long)]
        to_pubkey: String,
        #[arg(long)]
        sale_price: Option<u64>,
    },
    /// Burn NFT.
    ///
    /// Builds a signed `BurnNFT` transaction and submits via `post /submit_raw`.
    BurnNft {
        #[arg(long)]
        from: String,
        #[arg(long)]
        nft_id: String,
    },
    /// Approve NFT transfer.
    ///
    /// Builds a signed `ApproveNFT` transaction and submits via `post /submit_raw`.
    ApproveNft {
        #[arg(long)]
        from: String,
        #[arg(long)]
        nft_id: String,
        #[arg(long)]
        approved_pubkey: Option<String>,
    },
    /// Get NFT info by ID.
    ///
    /// Request: GET `/nft/{id}` (rpc path as defined by server).
    GetNft {
        #[arg(long)]
        nft_id: String,
    },
    /// List all NFTs owned by an account.
    ///
    /// Request: GET `/nfts/{account_id}` (rpc path as defined by server).
    MyNfts {
        /// Account ID (hex) or path to keyfile
        #[arg(long)]
        account: String,
    },
    
    /// Deploy a wasm cell.
    ///
    /// Builds a signed `DeployCell` transaction and submits via `post /submit_raw`.
    DeployCell {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long, default_value = "0")]
        initial_balance: u64,
        #[arg(long)]
        manifest_file: Option<String>,
    },
    /// Deploy a token cell.
    ///
    /// Builds a signed `DeployToken` transaction and submits via `post /submit_raw`.
    DeployToken {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        symbol: String,
        #[arg(long)]
        decimals: u8,
        #[arg(long)]
        supply: u128,
    },
    /// Call a cell with calldata (optionally simulate only).
    ///
    /// `--simulate` uses the rpc simulation endpoint and does not submit a tx.
    /// Otherwise builds `CallCell` and submits via `post /submit_raw`.
    CallCell {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        calldata: String,
        #[arg(long, default_value = "0")]
        value: u64,
        #[arg(long, default_value = "1000000")]
        gas_limit: u64,
        /// Simulate without submitting
        #[arg(long)]
        simulate: bool,
    },
/// Upgrade cell (auto-builds from source if provided).
    ///
    /// Builds a signed `UpgradeCell` transaction and submits via `post /submit_raw`.
    UpgradeCell {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long)]
        manifest_file: Option<String>,
    },
    /// Rotate account key.
    ///
    /// Builds a signed `RotateKey` transaction and submits via `post /submit_raw`.
    RotateKey {
        #[arg(long)]
        from: String,
        #[arg(long)]
        new_pubkey: String,
    },
    /// Accept cell ownership.
    ///
    /// Builds a signed `AcceptOwnership` transaction and submits via `post /submit_raw`.
    AcceptOwnership {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
    },
    /// Make cell immutable.
    ///
    /// Builds a signed `MakeImmutable` transaction and submits via `post /submit_raw`.
    MakeImmutable {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
    },
    /// Close cell and reclaim rent deposit.
    ///
    /// Builds a signed `CloseCell` transaction and submits via `post /submit_raw`.
    CloseCell {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
    },
    /// Propose upgrade for a system-owned cell (validators only).
    ///
    /// Builds a signed proposal tx and submits via `post /submit_raw`.
    ProposeCellUpgrade {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long)]
        manifest_file: Option<String>,
        #[arg(long, default_value = "7200")]
        timelock_blocks: u64,
    },
    /// Propose ownership transfer for a system-owned cell (validators only).
    ///
    /// Builds a signed proposal tx and submits via `post /submit_raw`.
    ProposeCellOwnershipTransfer {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        new_owner: String,
        #[arg(long, default_value = "7200")]
        timelock_blocks: u64,
    },
    /// Propose making a system-owned cell immutable (validators only).
    ///
    /// Builds a signed proposal tx and submits via `post /submit_raw`.
    ProposeCellMakeImmutable {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long, default_value = "7200")]
        timelock_blocks: u64,
    },
    /// Vote on an active cell proposal (validators only).
    ///
    /// Builds a signed vote tx and submits via `post /submit_raw`.
    VoteCellProposal {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        approve: bool,
    },
    /// Execute a matured cell proposal (validators only).
    ///
    /// Builds a signed execution tx and submits via `post /submit_raw`.
    ExecuteCellProposal {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
    },
    /// Token transfer (fast path).
    ///
    /// Builds a signed `TokenTransfer` transaction and submits via `post /submit_raw`.
    TokenTransfer {
        #[arg(long)]
        from: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
    /// Token mint.
    ///
    /// Builds a signed `TokenMint` transaction and submits via `post /submit_raw`.
    TokenMint {
        #[arg(long)]
        from: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u128,
    },
    /// Token burn.
    ///
    /// Builds a signed `TokenBurn` transaction and submits via `post /submit_raw`.
    TokenBurn {
        #[arg(long)]
        from: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        amount: u128,
    },
    /// Propose token authority update (validators only).
    ///
    /// Builds a signed proposal tx and submits via `post /submit_raw`.
    ProposeTokenAuthority {
        #[arg(long)]
        from: String,
        #[arg(long)]
        token: String,
        /// New mint authority account (hex)
        #[arg(long)]
        mint_authority: Option<String>,
        /// Clear mint authority (set to none)
        #[arg(long)]
        clear_mint_authority: bool,
        /// New freeze authority account (hex)
        #[arg(long)]
        freeze_authority: Option<String>,
        /// Clear freeze authority (set to none)
        #[arg(long)]
        clear_freeze_authority: bool,
        #[arg(long, default_value = "7200")]
        voting_period_blocks: u64,
    },
    /// Vote on token authority proposal (validators only).
    ///
    /// Builds a signed vote tx and submits via `post /submit_raw`.
    VoteTokenAuthority {
        #[arg(long)]
        from: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        approve: bool,
    },
    /// Call cell chain (composability).
    ///
    /// `--simulate` runs against the rpc without submitting a tx.
    /// Otherwise builds `CallCellChain` and submits via `post /submit_raw`.
    CallChain {
        #[arg(long)]
        from: String,
        #[arg(long)]
        calls: String,
        #[arg(long, default_value = "5000000")]
        gas_limit: u64,
        /// Simulate without submitting
        #[arg(long)]
        simulate: bool,
    },
    /// Propose cell name.
    ///
    /// Builds a signed call into the name registry cell and submits via `post /submit_raw`.
    ProposeName {
        #[arg(long)]
        from: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        target: String,
        #[arg(long)]
        owner: String,
    },
    /// Vote on name proposal.
    ///
    /// Builds a signed call into the name registry cell and submits via `post /submit_raw`.
    VoteName {
        #[arg(long)]
        from: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        approve: bool,
    },
    /// Renew name registration.
    ///
    /// Builds a signed call into the name registry cell and submits via `post /submit_raw`.
    RenewName {
        #[arg(long)]
        from: String,
        #[arg(long)]
        name: String,
    },
    /// Transfer name ownership.
    ///
    /// Builds a signed call into the name registry cell and submits via `post /submit_raw`.
    TransferName {
        #[arg(long)]
        from: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        new_owner: String,
    },
    /// Propose a bonded url pattern for public http oracle access.
    ///
    /// Builds a signed call into the oracle governance cell and submits via `post /submit_raw`.
    ProposeUrl {
        #[arg(long)]
        from: String,
        #[arg(long)]
        url_pattern: String,
        /// Bond in trth
        #[arg(long)]
        bond: u64,
        #[arg(long, default_value = "7200")]
        voting_period_blocks: u64,
    },
    /// Validator vote on a url proposal.
    ///
    /// Builds a signed call into the oracle governance cell and submits via `post /submit_raw`.
    VoteUrl {
        #[arg(long)]
        from: String,
        #[arg(long)]
        url_pattern: String,
        #[arg(long)]
        approve: bool,
    },
    /// Report an approved url as malicious (70% proposer bond slash).
    ///
    /// Builds a signed call into the oracle governance cell and submits via `post /submit_raw`.
    ReportMaliciousUrl {
        #[arg(long)]
        from: String,
        #[arg(long)]
        url_pattern: String,
        #[arg(long, default_value = "malicious behavior")]
        evidence: String,
    },
    /// Upgrade cell visibility tier (private/public).
    ///
    /// Builds a signed visibility update transaction and submits via `post /submit_raw`.
    UpgradeVisibility {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        /// Set true for Public, false for Private
        #[arg(long, default_value_t = true)]
        public: bool,
    },
    
    // Manifest SDK commands (local, no rpc)
    /// Build cell from source (compile + generate manifest).
    ///
    /// Local only. Produces `.wasm` + `.manifest.json`.
    Build {
        #[arg(long)]
        source: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Create a new Rust cell project from SDK template.
    ///
    /// Local only. Extracts embedded template files.
    SdkNew {
        #[arg(long)]
        path: String,
    },
    /// Build an SDK cell project (path to project root).
    ///
    /// Local only. Produces `.wasm` + auto manifest.
    SdkBuild {
        #[arg(long)]
        path: String,
        #[arg(long)]
        output: Option<String>,
    },
    /// Build (optional) and deploy an SDK cell project.
    ///
    /// Builds a signed `DeployCell` transaction and submits via `post /submit_raw`.
    SdkDeploy {
        #[arg(long)]
        from: String,
        #[arg(long)]
        cell_id: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        bytecode_file: Option<String>,
        #[arg(long, default_value = "0")]
        initial_balance: u64,
        #[arg(long)]
        manifest_file: Option<String>,
        #[arg(long, default_value_t = false)]
        skip_build: bool,
    },
    /// Initialize manifest.json for a wasm file.
    ///
    /// Local only. Writes a scaffold manifest and embeds it in the wasm.
    ManifestInit {
        #[arg(long)]
        bytecode_file: String,
    },
    /// Verify manifest against bytecode (local pre-flight check).
    ///
    /// Local only. Ensures declared slots match bytecode usage.
    ManifestVerify {
        #[arg(long)]
        bytecode_file: String,
        #[arg(long)]
        manifest_file: String,
    },
    /// Compute manifest hash.
    ///
    /// Local only. Produces a deterministic hash of the manifest.
    ManifestHash {
        #[arg(long)]
        bytecode_file: String,
        #[arg(long)]
        manifest_file: String,
    },
}

/// Build cell from Rust source (compile + generate manifest).
///
/// Local only. Produces `.wasm` + `.manifest.json`.
/// - Cargo project: `cargo build --release --target truthlinked-cells`
/// - Single file: `rustc` to `cdylib`
/// - Reuses `manifest.auto.json` or `manifest.json` when present.
fn build_cell(source: &str, output: Option<&str>) -> Result<(String, String), Box<dyn std::error::Error>> {
    use std::process::Command;
    
    let source_path = std::path::Path::new(source);
    let output_wasm = output.unwrap_or_else(|| source.trim_end_matches(".rs")).to_string() + ".wasm";
    let output_manifest = output_wasm.replace(".wasm", ".manifest.json");
    
    println!(" Compiling {} → {}", source, output_wasm);
    
    // Check if this is a Cargo project (has Cargo.toml)
    let is_cargo_project = source_path.parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("Cargo.toml").exists())
        .unwrap_or(false);
    
    let compile_result = if is_cargo_project {
        // Use cargo build for projects with dependencies
        Command::new("cargo")
            .args(&[
                "build",
                "--release",
                "--target", "truthlinked-cells",
            ])
            .current_dir(source_path.parent().unwrap().parent().unwrap())
            .output()?
    } else {
        // Use rustc for single-file cells
        Command::new("rustc")
            .args(&[
                "--target", "truthlinked-cells",
                "--crate-type", "cdylib",
                "-C", "opt-level=z",
                "-C", "lto=yes",
                "-o", &output_wasm,
                source,
            ])
            .output()?
    };
    
    if !compile_result.status.success() {
        eprintln!(" Compilation failed:");
        eprintln!("{}", String::from_utf8_lossy(&compile_result.stderr));
        std::process::exit(1);
    }
    
    // If cargo build, copy from target/truthlinked-cells/release/
    if is_cargo_project {
        let crate_dir = source_path.parent().unwrap().parent().unwrap();
        let cargo_output = crate_dir.join("target/truthlinked-cells/release");
        let crate_name = crate_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Failed to detect crate name from source path")?
            .replace('-', "_");
        let preferred_wasm = cargo_output.join(format!("{}.wasm", crate_name));
        
        // Find the .wasm file (usually named after the crate)
        let wasm_files: Vec<_> = std::fs::read_dir(&cargo_output)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "wasm").unwrap_or(false))
            .collect();
        
        if preferred_wasm.exists() {
            std::fs::copy(preferred_wasm, &output_wasm)?;
        } else if let Some(wasm_file) = wasm_files
            .iter()
            .max_by_key(|e| {
                e.metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            })
        {
            std::fs::copy(wasm_file.path(), &output_wasm)?;
        } else {
            return Err("No WASM file found in cargo output".into());
        }
    }
    
    println!(" Compiled successfully");
    
    // Generate manifest
    let bytecode = std::fs::read(&output_wasm)?;

    if is_cargo_project {
        let crate_dir = source_path.parent().unwrap().parent().unwrap();
        let auto_manifest_candidates = [
            crate_dir.join("manifest.auto.json"),
            crate_dir.join("eth_mirror/manifest.auto.json"),
            crate_dir.join("manifest.json"),
        ];

        for candidate in auto_manifest_candidates {
            if !candidate.exists() {
                continue;
            }

            let candidate_str = candidate
                .to_str()
                .ok_or("Invalid manifest path (non-utf8)")?;

            match load_manifest_sets(candidate_str) {
                Ok((reads, writes, _commutative, _storage_key_specs)) => {
                    match truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                        &bytecode,
                        &reads,
                        &writes,
                        &_storage_key_specs,
                    ) {
                        Ok(()) => {
                            let manifest_json = std::fs::read_to_string(&candidate)?;
                            std::fs::write(&output_manifest, manifest_json)?;
                            println!(" Applied auto manifest: {}", candidate.display());
                            println!(" Manifest verified locally.");
                            if let Ok(manifest_json) = std::fs::read_to_string(&output_manifest) {
                                if let Err(err) = embed_manifest_section(&output_wasm, &manifest_json) {
                                    eprintln!(" WARN: failed to embed manifest section: {}", err);
                                }
                            }
                            return Ok((output_wasm, output_manifest));
                        }
                        Err(reason) => {
                            println!(
                                "  Auto manifest {} did not verify: {}",
                                candidate.display(),
                                reason
                            );
                        }
                    }
                }
                Err(err) => {
                    println!(
                        "  Could not parse auto manifest {}: {}",
                        candidate.display(),
                        err
                    );
                }
            }
        }
    }

    let has_storage_ops = truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
        &bytecode,
        &[],
        &[],
        &[],
    ).is_err();
    
    let manifest = serde_json::json!({
        "declared_reads": [],
        "declared_writes": [],
        "commutative_keys": [],
        "storage_key_specs": [],
        "_comment": if has_storage_ops {
            "  Bytecode contains storage operations. Fill in the arrays above with actual slot hashes."
        } else {
            " No storage operations detected. Empty manifest is valid."
        }
    });
    
    std::fs::write(&output_manifest, serde_json::to_string_pretty(&manifest)?)?;
    if let Ok(manifest_json) = std::fs::read_to_string(&output_manifest) {
        if let Err(err) = embed_manifest_section(&output_wasm, &manifest_json) {
            eprintln!(" WARN: failed to embed manifest section: {}", err);
        }
    }
    
    println!(" Generated manifest: {}", output_manifest);
    if has_storage_ops {
        println!("  WARNING: Cell uses storage. Edit manifest to declare slots.");
    } else {
        println!(" No storage operations. Manifest is complete.");
    }
    
    Ok((output_wasm, output_manifest))
}

/// Fetch account info and fail if the account does not exist.
///
/// Request: GET `/account/{account_id}`
/// Response: `{ found, balance, balance_trth, is_cell, ... }`
fn require_account_exists(
    client: &reqwest::blocking::Client,
    rpc: &str,
    account_id: &str,
) -> Result<RpcAccountInfo, Box<dyn std::error::Error>> {
    let info: RpcAccountInfo = client
        .get(format!("{}/account/{}", rpc, account_id))
        .send()?
        .json()?;
    if !info.found {
        return Err(format!("account {} not found", account_id).into());
    }
    Ok(info)
}

/// Fetch cell info and fail if the cell does not exist.
///
/// Request: GET `/cell/{cell_id}`
/// Response: `{ found, is_token, immutable, ... }`
fn require_cell_exists(
    client: &reqwest::blocking::Client,
    rpc: &str,
    cell_id: &str,
) -> Result<RpcCellInfo, Box<dyn std::error::Error>> {
    let info: RpcCellInfo = client
        .get(format!("{}/cell/{}", rpc, cell_id))
        .send()?
        .json()?;
    if !info.found {
        return Err(format!("cell {} not found", cell_id).into());
    }
    Ok(info)
}

/// Fetch cell info and ensure it is a token cell.
/// Used by token mint/burn/transfer commands.
fn require_token_cell(
    client: &reqwest::blocking::Client,
    rpc: &str,
    token_id: &str,
) -> Result<RpcCellInfo, Box<dyn std::error::Error>> {
    let info = require_cell_exists(client, rpc, token_id)?;
    if !info.is_token {
        return Err(format!("cell {} is not a token", token_id).into());
    }
    Ok(info)
}

/// Fetch the chain's genesis hash (used as `chain_id` in tx signing).
///
/// Request: GET `/chain_info`
/// Response: `{ genesis_hash }`
fn fetch_genesis_hash(
    client: &reqwest::blocking::Client,
    rpc: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let chain_info: Value = client.get(format!("{}/chain_info", rpc)).send()?.json()?;
    let genesis_hash_hex = chain_info["genesis_hash"]
        .as_str()
        .ok_or("No genesis hash")?;
    let mut genesis_hash = [0u8; 32];
    hex::decode_to_slice(genesis_hash_hex, &mut genesis_hash)?;
    Ok(genesis_hash)
}

/// Serialize a json value according to the CLI output mode.
fn json_string(
    value: &Value,
    output: OutputFormat,
) -> Result<String, Box<dyn std::error::Error>> {
    match output {
        OutputFormat::Pretty => Ok(serde_json::to_string_pretty(value)?),
        OutputFormat::Json => Ok(serde_json::to_string(value)?),
    }
}

/// Print a json value using the selected output mode.
fn print_json(
    value: &Value,
    output: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", json_string(value, output)?);
    Ok(())
}

/// Recursively write an embedded template directory to disk.
fn write_embedded_dir(
    dir: &Dir,
    target: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    for subdir in dir.dirs() {
        write_embedded_dir(subdir, target)?;
    }
    for file in dir.files() {
        let out_path = target.join(file.path());
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&out_path, file.contents())?;
    }
    Ok(())
}

/// Parse a `CallChain` json payload into a typed list of cell calls.
/// Performs structural validation and size limits before submission.
fn parse_call_chain_json(
    calls: &str,
) -> Result<Vec<pq_execution::CellCall>, Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_str(calls)?;
    let calls_arr = value.as_array().ok_or("call-chain JSON must be an array")?;
    if calls_arr.len() > constants::MAX_CALL_CHAIN_CALLS {
        return Err(format!(
            "call-chain has {} calls, max allowed is {}",
            calls_arr.len(),
            constants::MAX_CALL_CHAIN_CALLS
        ).into());
    }

    let mut cell_calls = Vec::with_capacity(calls_arr.len());
    let allowed_fields: HashSet<&str> =
        ["cell", "calldata", "value", "use_result_from"].into_iter().collect();
    let mut total_calldata = 0usize;

    for (idx, call) in calls_arr.iter().enumerate() {
        let obj = call.as_object().ok_or("each call must be a JSON object")?;
        for key in obj.keys() {
            if !allowed_fields.contains(key.as_str()) {
                return Err(format!("call {} has unknown field '{}'", idx, key).into());
            }
        }

        let cell_hex = obj.get("cell")
            .and_then(|v| v.as_str())
            .ok_or("Missing cell")?;
        let cell_bytes = hex::decode(cell_hex)?;
        if cell_bytes.len() != 32 {
            return Err(format!("cell must be 32 bytes (64 hex chars), got {}", cell_hex.len()).into());
        }
        let mut cell_arr = [0u8; 32];
        cell_arr.copy_from_slice(&cell_bytes);

        let calldata_hex = obj.get("calldata")
            .and_then(|v| v.as_str())
            .ok_or("Missing calldata")?;
        let calldata = hex::decode(calldata_hex)?;
        if calldata.len() > constants::MAX_CALLDATA_SIZE {
            return Err(format!(
                "calldata too large: {} bytes (max: {})",
                calldata.len(),
                constants::MAX_CALLDATA_SIZE
            ).into());
        }
        total_calldata = total_calldata.saturating_add(calldata.len());
        if total_calldata > constants::MAX_CALL_CHAIN_TOTAL_CALLDATA {
            return Err(format!(
                "call-chain total calldata too large: {} bytes (max: {})",
                total_calldata,
                constants::MAX_CALL_CHAIN_TOTAL_CALLDATA
            ).into());
        }

        let value = match obj.get("value") {
            Some(v) => v.as_u64().ok_or("value must be a non-negative integer")? as u128,
            None => 0,
        };

        let use_result_from = match obj.get("use_result_from") {
            Some(v) => {
                let idx_val = v.as_u64().ok_or("use_result_from must be a non-negative integer")? as usize;
                if idx_val >= idx {
                    return Err(format!("use_result_from must reference a prior call ({} >= {})", idx_val, idx).into());
                }
                Some(idx_val)
            }
            None => None,
        };

        cell_calls.push(pq_execution::CellCall {
            cell_id: cell_arr,
            calldata,
            value,
            use_result_from,
        });
    }

    Ok(cell_calls)
}

const SYSTEM_CONTROLLER_GAS_LIMIT: u64 = 200_000;
const VALIDATOR_PUBKEY_LEN: usize = 1952;

/// Compute a 4-byte method selector from a function name.
/// Used by system cell call encoding.
fn selector_of(name: &str) -> [u8; 4] {
    let mut hash: u32 = 0x811c9dc5;
    for b in name.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash.to_le_bytes()
}

/// Encode name registry `propose` calldata.
fn encode_name_registry_propose(name: &str, target: [u8; 32], owner: [u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len() + 64);
    calldata.extend_from_slice(&selector_of("propose_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    calldata.extend_from_slice(&target);
    calldata.extend_from_slice(&owner);
    Ok(calldata)
}

/// Encode name registry `vote` calldata.
fn encode_name_registry_vote(name: &str, approve: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len() + 1);
    calldata.extend_from_slice(&selector_of("vote_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    calldata.push(if approve { 1 } else { 0 });
    Ok(calldata)
}

/// Encode name registry `renew` calldata.
fn encode_name_registry_renew(name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len());
    calldata.extend_from_slice(&selector_of("renew_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    Ok(calldata)
}

/// Encode name registry `transfer` calldata.
fn encode_name_registry_transfer(name: &str, new_owner: [u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > u8::MAX as usize {
        return Err("name too long (max 255 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 1 + name_bytes.len() + 32);
    calldata.extend_from_slice(&selector_of("transfer_name"));
    calldata.push(name_bytes.len() as u8);
    calldata.extend_from_slice(name_bytes);
    calldata.extend_from_slice(&new_owner);
    Ok(calldata)
}

/// Encode token authority `propose` calldata.
fn encode_token_authority_propose(
    token_cell: [u8; 32],
    set_mint: bool,
    mint_authority: [u8; 32],
    set_freeze: bool,
    freeze_authority: [u8; 32],
    voting_period_blocks: u64,
) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 1 + 32 + 1 + 32 + 8);
    calldata.extend_from_slice(&selector_of("propose_authority"));
    calldata.extend_from_slice(&token_cell);
    calldata.push(if set_mint { 1 } else { 0 });
    calldata.extend_from_slice(&mint_authority);
    calldata.push(if set_freeze { 1 } else { 0 });
    calldata.extend_from_slice(&freeze_authority);
    calldata.extend_from_slice(&voting_period_blocks.to_le_bytes());
    calldata
}

/// Encode token authority `vote` calldata.
fn encode_token_authority_vote(token_cell: [u8; 32], approve: bool) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 1);
    calldata.extend_from_slice(&selector_of("vote_authority"));
    calldata.extend_from_slice(&token_cell);
    calldata.push(if approve { 1 } else { 0 });
    calldata
}

/// Encode oracle governance `propose_url` calldata.
fn encode_oracle_propose_url(url: &str, bond_amount: u128, voting_period_blocks: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let url_bytes = url.as_bytes();
    if url_bytes.len() > u16::MAX as usize {
        return Err("url_pattern too long (max 65535 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 2 + url_bytes.len() + 16 + 8);
    calldata.extend_from_slice(&selector_of("propose_url"));
    calldata.extend_from_slice(&(url_bytes.len() as u16).to_le_bytes());
    calldata.extend_from_slice(url_bytes);
    calldata.extend_from_slice(&bond_amount.to_le_bytes());
    calldata.extend_from_slice(&voting_period_blocks.to_le_bytes());
    Ok(calldata)
}

/// Encode oracle governance `vote_url` calldata.
fn encode_oracle_vote_url(url: &str, approve: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let url_bytes = url.as_bytes();
    if url_bytes.len() > u16::MAX as usize {
        return Err("url_pattern too long (max 65535 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 2 + url_bytes.len() + 1);
    calldata.extend_from_slice(&selector_of("vote_url"));
    calldata.extend_from_slice(&(url_bytes.len() as u16).to_le_bytes());
    calldata.extend_from_slice(url_bytes);
    calldata.push(if approve { 1 } else { 0 });
    Ok(calldata)
}

/// Encode oracle governance `report_malicious` calldata.
fn encode_oracle_report_malicious(url: &str, evidence: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let url_bytes = url.as_bytes();
    let ev_bytes = evidence.as_bytes();
    if url_bytes.len() > u16::MAX as usize {
        return Err("url_pattern too long (max 65535 bytes)".into());
    }
    if ev_bytes.len() > u16::MAX as usize {
        return Err("evidence too long (max 65535 bytes)".into());
    }
    let mut calldata = Vec::with_capacity(4 + 2 + url_bytes.len() + 2 + ev_bytes.len());
    calldata.extend_from_slice(&selector_of("report_malicious"));
    calldata.extend_from_slice(&(url_bytes.len() as u16).to_le_bytes());
    calldata.extend_from_slice(url_bytes);
    calldata.extend_from_slice(&(ev_bytes.len() as u16).to_le_bytes());
    calldata.extend_from_slice(ev_bytes);
    Ok(calldata)
}

/// Encode staking `stake` calldata for the staking controller cell.
fn encode_staking_stake(pubkey: &[u8], amount: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("stake"));
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `unstake` calldata for the staking controller cell.
fn encode_staking_unstake(pubkey: &[u8], amount: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("unstake"));
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `withdraw` calldata for the staking controller cell.
fn encode_staking_withdraw(pubkey: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("withdraw"));
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Encode staking `unjail` calldata for the staking controller cell.
fn encode_staking_unjail(pubkey: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("unjail"));
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Encode vetrth `lock` calldata.
fn encode_vetrth_lock(owner: [u8; 32], lock_blocks: u64) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 8);
    calldata.extend_from_slice(&selector_of("lock"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(&lock_blocks.to_le_bytes());
    calldata
}

/// Encode vetrth `extend` calldata.
fn encode_vetrth_extend(owner: [u8; 32], lock_blocks: u64) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 8);
    calldata.extend_from_slice(&selector_of("extend"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(&lock_blocks.to_le_bytes());
    calldata
}

/// Encode vetrth `unlock` calldata.
fn encode_vetrth_unlock(owner: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("unlock"));
    calldata.extend_from_slice(&owner);
    calldata
}

/// Encode treasury `propose` calldata.
fn encode_treasury_propose(
    proposal_id: [u8; 32],
    bucket: u64,
    recipient: [u8; 32],
    amount: u128,
    timelock_blocks: u64,
) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 8 + 32 + 16 + 8);
    calldata.extend_from_slice(&selector_of("propose_spend"));
    calldata.extend_from_slice(&proposal_id);
    calldata.extend_from_slice(&bucket.to_le_bytes());
    calldata.extend_from_slice(&recipient);
    calldata.extend_from_slice(&amount.to_le_bytes());
    calldata.extend_from_slice(&timelock_blocks.to_le_bytes());
    calldata
}

/// Encode treasury `vote` calldata.
fn encode_treasury_vote(proposal_id: [u8; 32], approve: bool) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 1);
    calldata.extend_from_slice(&selector_of("vote_spend"));
    calldata.extend_from_slice(&proposal_id);
    calldata.push(if approve { 1 } else { 0 });
    calldata
}

/// Encode treasury `execute` calldata.
fn encode_treasury_execute(proposal_id: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("execute_spend"));
    calldata.extend_from_slice(&proposal_id);
    calldata
}

/// Parse a 32-byte hex account ID string into `[u8; 32]`.
fn parse_account_id_hex(value: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err("account id must be 32 bytes (64 hex chars)".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}


/// Encode staking delegate `add` calldata.
fn encode_staking_delegate_add(delegate: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("delegate_add"));
    calldata.extend_from_slice(&delegate);
    calldata
}

/// Encode staking delegate `remove` calldata.
fn encode_staking_delegate_remove(delegate: [u8; 32]) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector_of("delegate_remove"));
    calldata.extend_from_slice(&delegate);
    calldata
}

/// Encode staking `stake_for` calldata (delegate path).
fn encode_staking_stake_for(owner: [u8; 32], pubkey: &[u8], amount: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("stake_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `unstake_for` calldata (delegate path).
fn encode_staking_unstake_for(owner: [u8; 32], pubkey: &[u8], amount: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN + 8);
    calldata.extend_from_slice(&selector_of("unstake_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    calldata.extend_from_slice(&amount.to_le_bytes());
    Ok(calldata)
}

/// Encode staking `withdraw_for` calldata (delegate path).
fn encode_staking_withdraw_for(owner: [u8; 32], pubkey: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("withdraw_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Encode staking `unjail_for` calldata (delegate path).
fn encode_staking_unjail_for(owner: [u8; 32], pubkey: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if pubkey.len() != VALIDATOR_PUBKEY_LEN {
        return Err("validator pubkey must be 1952 bytes".into());
    }
    let mut calldata = Vec::with_capacity(4 + 32 + VALIDATOR_PUBKEY_LEN);
    calldata.extend_from_slice(&selector_of("unjail_for"));
    calldata.extend_from_slice(&owner);
    calldata.extend_from_slice(pubkey);
    Ok(calldata)
}

/// Parse a list of 32-byte hex strings into slot keys.
fn parse_manifest_slots(
    manifest: &serde_json::Value,
    field: &str,
) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
    manifest[field]
        .as_array()
        .ok_or_else(|| format!("Missing {} in manifest", field))?
        .iter()
        .map(|v| {
            let hex = v
                .as_str()
                .ok_or_else(|| format!("Invalid {} entry", field))?;
            let bytes = hex::decode(hex)?;
            if bytes.len() != 32 {
                return Err(format!("{} entry must be 32 bytes", field).into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()
}

/// Load manifest fields (reads/writes/commutative/specs) from a json file.
fn load_manifest_sets(
    manifest_path: &str,
) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<truthlinked::cells::StorageKeySpec>), Box<dyn std::error::Error>> {
    let manifest_json = std::fs::read_to_string(manifest_path)?;
    load_manifest_sets_from_json(&manifest_json)
}

/// Parse storage key specs from manifest json.
fn parse_manifest_specs(
    manifest: &serde_json::Value,
) -> Result<Vec<truthlinked::cells::StorageKeySpec>, Box<dyn std::error::Error>> {
    let specs = manifest
        .get("storage_key_specs")
        .and_then(|v| v.as_array())
        .ok_or("Missing storage_key_specs in manifest")?;
    let mut out = Vec::new();
    for item in specs {
        let offset = item.get("offset").and_then(|v| v.as_u64())
            .ok_or("Invalid storage_key_specs.offset")?;
        let len = item.get("len").and_then(|v| v.as_u64())
            .ok_or("Invalid storage_key_specs.len")?;
        out.push(truthlinked::cells::StorageKeySpec {
            offset: offset as usize,
            len: len as usize,
        });
    }
    Ok(out)
}

/// Load manifest fields directly from json bytes.
fn load_manifest_sets_from_json(
    manifest_json: &str,
) -> Result<(Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<[u8; 32]>, Vec<truthlinked::cells::StorageKeySpec>), Box<dyn std::error::Error>> {
    let manifest: serde_json::Value = serde_json::from_str(manifest_json)?;
    let declared_reads = parse_manifest_slots(&manifest, "declared_reads")?;
    let declared_writes = parse_manifest_slots(&manifest, "declared_writes")?;
    let commutative_keys = parse_manifest_slots(&manifest, "commutative_keys")?;
    let storage_key_specs = parse_manifest_specs(&manifest)?;
    Ok((declared_reads, declared_writes, commutative_keys, storage_key_specs))
}

/// Encode a u32 as uleb128 (used for custom wasm sections).
fn encode_uleb_u32(mut value: u32, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        } else {
            out.push(byte | 0x80);
        }
    }
}

/// Decode a u32 from uleb128 (used for custom wasm sections).
fn decode_uleb_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, String> {
    let mut result: u32 = 0;
    let mut shift = 0;
    loop {
        if *cursor >= bytes.len() {
            return Err("ULEB decode overflow".to_string());
        }
        let byte = bytes[*cursor];
        *cursor += 1;
        result |= ((byte & 0x7f) as u32) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift > 28 {
            return Err("ULEB decode too large".to_string());
        }
    }
}

/// Embed the manifest json into a custom wasm section (`truthlinked.manifest`).
fn embed_manifest_section(wasm_path: &str, manifest_json: &str) -> Result<(), Box<dyn std::error::Error>> {
    const SECTION_NAME: &str = "truthlinked.manifest";
    let mut wasm = std::fs::read(wasm_path)?;

    let mut payload = Vec::new();
    encode_uleb_u32(SECTION_NAME.len() as u32, &mut payload);
    payload.extend_from_slice(SECTION_NAME.as_bytes());
    payload.extend_from_slice(manifest_json.as_bytes());

    let mut section = Vec::new();
    section.push(0); // custom section id
    encode_uleb_u32(payload.len() as u32, &mut section);
    section.extend_from_slice(&payload);

    wasm.extend_from_slice(&section);
    std::fs::write(wasm_path, wasm)?;
    Ok(())
}

/// Extract the manifest json from a wasm custom section, if present.
fn extract_manifest_section(wasm_bytes: &[u8]) -> Result<Option<String>, String> {
    const MAGIC: &[u8; 4] = b"\0asm";
    const VERSION: &[u8; 4] = b"\x01\0\0\0";
    const SECTION_NAME: &str = "truthlinked.manifest";

    if wasm_bytes.len() < 8 || &wasm_bytes[0..4] != MAGIC || &wasm_bytes[4..8] != VERSION {
        return Err("Invalid WASM header".to_string());
    }

    let mut cursor = 8usize;
    while cursor < wasm_bytes.len() {
        let id = wasm_bytes[cursor];
        cursor += 1;
        let section_len = decode_uleb_u32(wasm_bytes, &mut cursor)? as usize;
        if cursor + section_len > wasm_bytes.len() {
            return Err("WASM section length out of bounds".to_string());
        }
        if id == 0 {
            let mut name_cursor = cursor;
            let name_len = decode_uleb_u32(wasm_bytes, &mut name_cursor)? as usize;
            if name_cursor + name_len <= cursor + section_len {
                let name = &wasm_bytes[name_cursor..name_cursor + name_len];
                if name == SECTION_NAME.as_bytes() {
                    let data_start = name_cursor + name_len;
                    let data_end = cursor + section_len;
                    let json = String::from_utf8(wasm_bytes[data_start..data_end].to_vec())
                        .map_err(|_| "Manifest section is not valid UTF-8".to_string())?;
                    return Ok(Some(json));
                }
            }
        }
        cursor += section_len;
    }

    Ok(None)
}

/// Read `[package].name` from Cargo.toml.
fn parse_package_name(cargo_toml: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(cargo_toml)?;
    let parsed: toml::Value = toml::from_str(&content)?;
    let name = parsed
        .get("package")
        .and_then(|pkg| pkg.get("name"))
        .and_then(|v| v.as_str())
        .ok_or("Could not parse package.name from Cargo.toml")?;
    Ok(name.to_string())
}

/// Build an SDK project and return (wasm_path, manifest_path).
fn sdk_build_project(
    project_path: &str,
    output: Option<&str>,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(project_path);
    let source = root.join("src/lib.rs");
    if !source.exists() {
        return Err(format!("SDK source not found: {}", source.display()).into());
    }

    let _ = sdk_generate_manifest(root);

    let output_base = if let Some(explicit) = output {
        explicit.to_string()
    } else {
        let build_dir = root.join("build");
        std::fs::create_dir_all(&build_dir)?;
        build_dir.join("cell").to_string_lossy().to_string()
    };

    build_cell(source.to_string_lossy().as_ref(), Some(&output_base))
}

/// Generate a manifest scaffold for an SDK project.
fn sdk_generate_manifest(root: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;

    let manifest_bin = root.join("src/bin/manifest.rs");
    if !manifest_bin.exists() {
        return Ok(());
    }

    let out_path = root.join("manifest.auto.json");
    let status = Command::new("cargo")
        .args(&["run", "--quiet", "--bin", "manifest", "--release"])
        .current_dir(root)
        .env("TRUTHLINKED_MANIFEST_OUT", out_path.to_string_lossy().to_string())
        .status()?;

    if !status.success() {
        eprintln!(" WARN: manifest auto-generation failed; continuing with fallback.");
        return Ok(());
    }

    let _ = sdk_augment_manifest_from_source(root, &out_path);
    Ok(())
}

/// Augment the manifest by scanning Rust source for SDK storage patterns.
/// This helper does not replace a manual review.
fn sdk_augment_manifest_from_source(
    root: &std::path::Path,
    manifest_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let src_root = root.join("src");
    if !src_root.exists() || !manifest_path.exists() {
        return Ok(());
    }

    let sources = read_project_sources(&src_root)?;
    if sources.is_empty() {
        return Ok(());
    }
    let joined = sources.join("\n");
    let consts = parse_const_offsets(&joined);
    let mut specs = Vec::new();
    let var_offsets = collect_var_key_bindings(&joined, &consts);
    for prefix in [
        "abi::read_account",
        "abi::read_account_id",
        "abi::read_bytes32",
        "truthlinked_sdk::abi::read_account",
        "crate::abi::read_account",
    ] {
        collect_key_specs(&joined, prefix, &consts, &mut specs);
    }
    collect_key_specs_from_storage_calls(&joined, &consts, &var_offsets, &mut specs);

    if specs.is_empty() {
        return Ok(());
    }

    let manifest_json = std::fs::read_to_string(manifest_path)?;
    let mut manifest: serde_json::Value = serde_json::from_str(&manifest_json)?;
    let array = manifest
        .get_mut("storage_key_specs")
        .and_then(|v| v.as_array_mut())
        .ok_or("manifest storage_key_specs missing or not array")?;

    let mut existing = std::collections::HashSet::new();
    for item in array.iter() {
        if let (Some(offset), Some(len)) = (item.get("offset"), item.get("len")) {
            if let (Some(offset), Some(len)) = (offset.as_u64(), len.as_u64()) {
                existing.insert((offset as usize, len as usize));
            }
        }
    }

    for (offset, len) in specs {
        if existing.insert((offset, len)) {
            array.push(serde_json::json!({ "offset": offset, "len": len }));
        }
    }

    // Sort for determinism.
    array.sort_by(|a, b| {
        let ao = a.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
        let bo = b.get("offset").and_then(|v| v.as_u64()).unwrap_or(0);
        let al = a.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        let bl = b.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        ao.cmp(&bo).then(al.cmp(&bl))
    });

    std::fs::write(manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    Ok(())
}

/// Recursively read Rust source files for SDK analysis.
fn read_project_sources(root: &std::path::Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    fn visit(dir: &std::path::Path, out: &mut Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                visit(&path, out)?;
            } else if let Some(ext) = path.extension() {
                if ext == "rs" {
                    if let Ok(text) = std::fs::read_to_string(&path) {
                        out.push(text);
                    }
                }
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    visit(root, &mut out)?;
    Ok(out)
}

/// Parse `const` offsets from Rust source for manifest augmentation.
fn parse_const_offsets(source: &str) -> std::collections::HashMap<String, usize> {
    use regex::Regex;
    let mut map = std::collections::HashMap::new();
    let mut raw_map = std::collections::HashMap::new();
    let re = Regex::new(r"(?m)^\s*(?:pub\s+)?(?:const|static)\s+([A-Z0-9_]+)\s*:\s*(?:usize|u32|u64)\s*=\s*([^;]+);").ok();
    if let Some(re) = re {
        for caps in re.captures_iter(source) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let raw = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim().to_string();
            raw_map.insert(name, raw);
        }
    }

    // Resolve constants with simple expressions (literals and additions).
    for _ in 0..4 {
        let mut progressed = false;
        for (name, raw) in raw_map.iter() {
            if map.contains_key(name) {
                continue;
            }
            if let Some(value) = resolve_offset_expr(raw, &map) {
                map.insert(name.clone(), value);
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    map
}

/// Parse a Rust usize literal (decimal or hex).
fn parse_usize_literal(raw: &str) -> Option<usize> {
    let s = raw.replace('_', "");
    if let Some(hex) = s.strip_prefix("0x") {
        usize::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<usize>().ok()
    }
}

/// Resolve an offset expression using the known const table.
fn resolve_offset_expr(expr: &str, consts: &std::collections::HashMap<String, usize>) -> Option<usize> {
    let mut cleaned = expr.replace(' ', "");
    while cleaned.starts_with('(') && cleaned.ends_with(')') && cleaned.len() > 2 {
        cleaned = cleaned[1..cleaned.len() - 1].to_string();
    }
    if let Some(v) = parse_usize_literal(&cleaned) {
        return Some(v);
    }
    if let Some(v) = consts.get(&cleaned) {
        return Some(*v);
    }
    if let Some((a, b)) = cleaned.split_once('+') {
        let left = resolve_offset_expr(a, consts)?;
        let right = resolve_offset_expr(b, consts)?;
        return left.checked_add(right);
    }
    None
}

/// Collect storage key specs from extracted patterns.
fn collect_key_specs(
    source: &str,
    fn_prefix: &str,
    consts: &std::collections::HashMap<String, usize>,
    out: &mut Vec<(usize, usize)>,
) {
    use regex::Regex;
    let pattern = format!(
        r"(?s){}\s*\(\s*[^,]+,\s*([A-Za-z0-9_+\s]+)\s*\)",
        regex::escape(fn_prefix)
    );
    let re = match Regex::new(&pattern) {
        Ok(v) => v,
        Err(_) => return,
    };
    for caps in re.captures_iter(source) {
        let expr = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if let Some(offset) = resolve_offset_expr(expr, consts) {
            out.push((offset, 32));
        }
    }
}

/// Collect variable bindings used in derived storage slots.
fn collect_var_key_bindings(
    source: &str,
    consts: &std::collections::HashMap<String, usize>,
) -> std::collections::HashMap<String, usize> {
    use regex::Regex;
    let mut out = std::collections::HashMap::new();
    let prefixes = [
        "abi::read_account",
        "abi::read_account_id",
        "abi::read_bytes32",
        "truthlinked_sdk::abi::read_account",
        "crate::abi::read_account",
    ];
    for prefix in prefixes {
        let pattern = format!(
            r"(?s)let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{}\s*\(\s*[^,]+,\s*([A-Za-z0-9_+\s]+)\s*\)",
            regex::escape(prefix)
        );
        let re = match Regex::new(&pattern) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for caps in re.captures_iter(source) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
            let expr = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            if let Some(offset) = resolve_offset_expr(expr, consts) {
                out.insert(name, offset);
            }
        }
    }
    out
}

/// Normalize a storage key expression for deterministic matching.
fn normalize_key_expr(expr: &str) -> String {
    let mut s = expr.trim().to_string();
    if let Some(stripped) = s.strip_prefix('&') {
        s = stripped.trim().to_string();
    }
    for suffix in [".as_bytes()", ".as_ref()", ".as_slice()"] {
        if let Some(stripped) = s.strip_suffix(suffix) {
            s = stripped.trim().to_string();
        }
    }
    if s.starts_with('(') && s.ends_with(')') && s.len() > 2 {
        s = s[1..s.len() - 1].trim().to_string();
    }
    s
}

/// Scan SDK storage calls to extract storage key specs.
fn collect_key_specs_from_storage_calls(
    source: &str,
    consts: &std::collections::HashMap<String, usize>,
    var_offsets: &std::collections::HashMap<String, usize>,
    out: &mut Vec<(usize, usize)>,
) {
    use regex::Regex;
    let patterns = [
        r"(?s)storage::slot_for\s*\(\s*[^,]+,\s*([^\)]+)\)",
        r"(?s)hashing::derive_slot\s*\(\s*[^,]+,\s*&?\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)hashing::derive_slot\s*\(\s*[^,]+,\s*&?\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)hashing::derive_slot\s*\(\s*[^,]+,\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)Slot::derived\s*\(\s*[^,]+,\s*&?\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)Slot::derived\s*\(\s*[^,]+,\s*&?\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)storage::Slot::derived\s*\(\s*[^,]+,\s*&?\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)storage::Slot::derived\s*\(\s*[^,]+,\s*&?\s*vec!\s*\[\s*([^\]]+)\]\s*\)",
        r"(?s)\.\s*(?:get|insert|remove|contains)_typed_key\s*\(\s*([^\),]+)",
        r"(?s)\.\s*(?:get|insert|remove|contains)_key\s*\(\s*([^\),]+)",
        r"(?s)\.\s*slots_for_key\s*\(\s*([^\)]+)\)",
    ];

    for pat in patterns {
        let re = match Regex::new(pat) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for caps in re.captures_iter(source) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let mut expr = normalize_key_expr(raw);
            expr = extract_key_expr_from_list(&expr);
            // Inline abi::read_* usage
            for prefix in [
                "abi::read_account",
                "abi::read_account_id",
                "abi::read_bytes32",
                "truthlinked_sdk::abi::read_account",
                "crate::abi::read_account",
            ] {
                if expr.starts_with(prefix) {
                    if let Some(idx) = expr.find(',') {
                        let after = &expr[idx + 1..];
                        if let Some(end) = after.find(')') {
                            let offset_expr = after[..end].trim();
                            if let Some(offset) = resolve_offset_expr(offset_expr, consts) {
                                out.push((offset, 32));
                            }
                        }
                    }
                }
            }

            // Variable backed by abi::read_* binding
            if let Some(offset) = var_offsets.get(&expr) {
                out.push((*offset, 32));
            }
        }
    }
}

/// Extract key expressions from list-style syntax.
fn extract_key_expr_from_list(expr: &str) -> String {
    // Handle hashing::derive_slot(_, &[..., key]) where we need the last element.
    if expr.contains(',') {
        let mut parts = expr.split(',');
        let mut last = "";
        for part in parts.by_ref() {
            last = part;
        }
        return normalize_key_expr(last);
    }
    expr.to_string()
}

/// Locate the built wasm artifact for an SDK project.
fn sdk_locate_wasm(project_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let root = std::path::Path::new(project_path);

    let build_candidate = root.join("build/cell.wasm");
    if build_candidate.exists() {
        return Ok(build_candidate.to_string_lossy().to_string());
    }

    let cargo_toml = root.join("Cargo.toml");
    if !cargo_toml.exists() {
        return Err(format!("Cargo.toml not found in {}", root.display()).into());
    }
    let crate_name = parse_package_name(&cargo_toml)?.replace('-', "_");
    let release_candidate = root
        .join("target/truthlinked-cells/release")
        .join(format!("{}.wasm", crate_name));
    if release_candidate.exists() {
        return Ok(release_candidate.to_string_lossy().to_string());
    }

    Err(format!(
        "No wasm artifact found for SDK project {}. Run `trth-cli sdk-build --path {}` first.",
        root.display(),
        project_path
    )
    .into())
}

/// Resolve manifest path, preferring explicit override if provided.
fn resolve_manifest_path(wasm_path: &str, manifest_override: Option<String>) -> Option<String> {
    if manifest_override.is_some() {
        return manifest_override;
    }
    let inferred = wasm_path.replace(".wasm", ".manifest.json");
    if std::path::Path::new(&inferred).exists() {
        Some(inferred)
    } else {
        None
    }
}

/// Submit a `DeployCell` transaction using the given wasm/manifest.
fn submit_cell_deploy(
    client: &reqwest::blocking::Client,
    rpc: &str,
    from: &str,
    cell_id: &str,
    wasm_path: &str,
    manifest_path: Option<String>,
    initial_balance: u64,
    output: OutputFormat,
) -> Result<(), Box<dyn std::error::Error>> {
    let sender_keys = DualKeypair::load(from)?;
    let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
    let sender_account_id = truthlinked::pq_identity::account_id_from_pubkey(&pubkey);

    let cell_id_bytes = hex::decode(cell_id)?;
    if cell_id_bytes.len() != 32 {
        return Err("cell_id must be 32 bytes hex".into());
    }
    let mut cell_id_arr = [0u8; 32];
    cell_id_arr.copy_from_slice(&cell_id_bytes);

    let bytecode = std::fs::read(wasm_path)?;
    let (declared_reads, declared_writes, commutative_keys, storage_key_specs) =
        if let Some(manifest_path) = manifest_path {
            let (reads, writes, commutative, specs) = load_manifest_sets(&manifest_path)?;
            truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                &bytecode,
                &reads,
                &writes,
                &specs,
            )?;
            eprintln!(" Manifest verified locally: {}", manifest_path);
            (reads, writes, commutative, specs)
        } else if let Ok(Some(manifest_json)) = extract_manifest_section(&bytecode) {
            let (reads, writes, commutative, specs) = load_manifest_sets_from_json(&manifest_json)?;
            truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                &bytecode,
                &reads,
                &writes,
                &specs,
            )?;
            eprintln!(" Manifest extracted from WASM and verified locally.");
            (reads, writes, commutative, specs)
        } else {
            return Err("No manifest found. Build with the SDK (auto-embeds) or provide --manifest-file.".into());
        };

    let genesis_hash = fetch_genesis_hash(client, rpc)?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let tx = Transaction {
        sender: sender_account_id,
        intent: TransactionIntent::DeployCell {
            cell_id: cell_id_arr,
            bytecode,
            initial_balance: initial_balance as u128,
            declared_reads,
            declared_writes,
            commutative_keys,
            storage_key_specs,
        },
        signature: vec![],
        timestamp,
        chain_id: genesis_hash,
        expiration_height: u64::MAX,
    };

    let signed_tx = sender_keys.sign_transaction(&tx)?;
    let tx_bytes = postcard::to_allocvec(&signed_tx)?;

    eprintln!("Submitting cell deployment...");
    let res: Value = client
        .post(format!("{}/submit_raw", rpc))
        .body(tx_bytes)
        .send()?
        .json()?;
    print_json(&res, output)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()?;
    
    match cli.command {
        Commands::ChainInfo => {
            let res: Value = client.get(format!("{}/chain_info", cli.rpc)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        Commands::TokenInfo => {
            let res: Value = client.get(format!("{}/token_info", cli.rpc)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        Commands::NetworkInfo => {
            let res: Value = client.get(format!("{}/network_info", cli.rpc)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        Commands::Validators => {
            let res: Value = client.get(format!("{}/validators", cli.rpc)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        Commands::Mempool => {
            let res: Value = client.get(format!("{}/mempool", cli.rpc)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        Commands::Resolve { query } => {
            let q = urlencoding::encode(&query);
            let res: Value = client.get(format!("{}/resolve/{}", cli.rpc, q)).send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::ListCellProposals => {
            let res: Value = client.get(format!("{}/cell_proposals", cli.rpc)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        Commands::TxStatus { hash } => {
            let resp = client.get(format!("{}/tx/{}", cli.rpc, hash)).send()?;
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                let pending: Value = client.get(format!("{}/mempool/tx/{}", cli.rpc, hash)).send()?.json()?;
                let found = pending.get("found").and_then(|v| v.as_bool()).unwrap_or(false);
                let out = if found {
                    serde_json::json!({
                        "status": "pending",
                        "tx": pending.get("transaction").cloned().unwrap_or(serde_json::Value::Null)
                    })
                } else {
                    serde_json::json!({
                        "status": "not_found",
                        "tx": serde_json::Value::Null
                    })
                };
                print_json(&out, cli.output)?;
                return Ok(());
            }
            if !resp.status().is_success() {
                return Err(format!("RPC error: status {}", resp.status()).into());
            }
            let confirmed: Value = resp.json()?;
            if let Some(err) = confirmed.get("error") {
                return Err(format!("RPC error: {}", err).into());
            }
            if !confirmed.is_null() {
                let out = serde_json::json!({
                    "status": "confirmed",
                    "tx": confirmed
                });
                print_json(&out, cli.output)?;
            } else {
                let pending: Value = client.get(format!("{}/mempool/tx/{}", cli.rpc, hash)).send()?.json()?;
                let found = pending.get("found").and_then(|v| v.as_bool()).unwrap_or(false);
                let out = if found {
                    serde_json::json!({
                        "status": "pending",
                        "tx": pending.get("transaction").cloned().unwrap_or(serde_json::Value::Null)
                    })
                } else {
                    serde_json::json!({
                        "status": "not_found",
                        "tx": serde_json::Value::Null
                    })
                };
                print_json(&out, cli.output)?;
            }
        }
        Commands::Balance { account_id } => {
            let res: Value = client.post(format!("{}/balance", cli.rpc))
                .json(&serde_json::json!({"account_id": account_id}))
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }
        Commands::BalanceByPubkey { pubkey } => {
            let res: Value = client.post(format!("{}/balance_by_pubkey", cli.rpc))
                .json(&serde_json::json!({"pubkey": pubkey}))
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }
        
        Commands::AccountId { from, pubkey } => {
            let pk_bytes = if let Some(keyfile) = from {
                let keypair = pq_identity::DualKeypair::load(&keyfile)?;
                keypair.dilithium_pk.into_bytes().to_vec()
            } else if let Some(pk_hex) = pubkey {
                hex::decode(&pk_hex)?
            } else {
                // Try default keyfile
                let default_path = default_keyfile_path();
                if std::path::Path::new(&default_path).exists() {
                    let keypair = pq_identity::DualKeypair::load(&default_path)?;
                    keypair.dilithium_pk.into_bytes().to_vec()
                } else {
                    return Err(format!("No keyfile found. Provide --from or --pubkey, or create default keyfile at {}", default_path).into());
                }
            };
            
            if pk_bytes.len() != 1952 {
                return Err(format!("Invalid public key length: {} (expected 1952 bytes)", pk_bytes.len()).into());
            }
            
            let account_id = pq_identity::account_id_from_pubkey(&pk_bytes);
            if matches!(cli.output, OutputFormat::Json) {
                let out = serde_json::json!({
                    "account_id": hex::encode(&account_id),
                    "public_key": hex::encode(&pk_bytes),
                });
                print_json(&out, cli.output)?;
            } else {
                println!("{}", hex::encode(&account_id));
            }
        }
        
        Commands::ImportMnemonic { mnemonic, output, passphrase } => {
            let keypair = if let Some(pass) = passphrase {
                pq_identity::DualKeypair::from_mnemonic_with_passphrase(mnemonic, &pass)
            } else {
                pq_identity::DualKeypair::from_mnemonic(mnemonic)
            };
            
            let password = rpassword::prompt_password("Enter password to encrypt keyfile: ")?;
            
            // Create ~/.truthlinked directory if saving to default location
            if output == default_keyfile_path() {
                if let Some(parent) = std::path::Path::new(&output).parent() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            
            keypair.save_with_password(&output, Some(&password))?;
            
            let pubkey = keypair.dilithium_pk.clone().into_bytes();
            let account_id = pq_identity::account_id_from_pubkey(&pubkey);

            if matches!(cli.output, OutputFormat::Json) {
                let out = serde_json::json!({
                    "status": "imported",
                    "keyfile": output,
                    "account_id": hex::encode(&account_id),
                    "public_key": hex::encode(&pubkey),
                });
                print_json(&out, cli.output)?;
            } else {
                println!(" Keypair imported successfully");
                println!("   Keyfile: {}", output);
                println!("   Account ID: {}", hex::encode(&account_id));
                println!("   Public Key: {}", hex::encode(&pubkey));
            }
        }
        Commands::AccountCreate { output, encrypt, passphrase } => {
            let mut entropy = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy)?;
            let keypair = if let Some(pass) = &passphrase {
                pq_identity::DualKeypair::from_mnemonic_with_passphrase(mnemonic.to_string(), pass)
            } else {
                pq_identity::DualKeypair::from_mnemonic(mnemonic.to_string())
            };

            let password = if encrypt {
                let password = rpassword::prompt_password("Enter password to encrypt keyfile: ")?;
                let confirm = rpassword::prompt_password("Confirm password: ")?;
                if password != confirm {
                    return Err("Passwords do not match".into());
                }
                if password.len() < 8 {
                    return Err("Password must be at least 8 characters".into());
                }
                Some(password)
            } else {
                eprintln!(" WARNING: Keyfile will be saved unencrypted");
                None
            };

            if output == default_keyfile_path() {
                if let Some(parent) = std::path::Path::new(&output).parent() {
                    std::fs::create_dir_all(parent)?;
                }
            }

            keypair.save_with_password(&output, password.as_deref())?;

            let pubkey = keypair.dilithium_pk.clone().into_bytes();
            let account_id = pq_identity::account_id_from_pubkey(&pubkey);

            if matches!(cli.output, OutputFormat::Json) {
                let out = serde_json::json!({
                    "status": "created",
                    "keyfile": output,
                    "account_id": hex::encode(&account_id),
                    "public_key": hex::encode(&pubkey),
                    "mnemonic": mnemonic.to_string(),
                    "passphrase_provided": passphrase.is_some(),
                });
                print_json(&out, cli.output)?;
                eprintln!(" WARNING: The mnemonic was printed to stdout. Treat it as sensitive.");
            } else {
                println!(" Keypair created");
                println!("   Keyfile: {}", output);
                println!("   Account ID: {}", hex::encode(&account_id));
                println!("   Public Key: {}", hex::encode(&pubkey));
                eprintln!(" WARNING: The mnemonic below controls this account.");
                eprintln!("          Do not paste it into terminals, logs, or CI.");
                eprintln!("   Mnemonic: {}", mnemonic);
                if passphrase.is_some() {
                    eprintln!("   Passphrase: (provided, must be remembered for recovery)");
                }
            }
        }
        
        Commands::Airdrop { from, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if amount == 0 {
                return Err("Amount must be > 0".into());
            }
            let amount_raw = (amount as u128) * ONE_TRTH;
            if amount_raw > constants::MAX_AIRDROP_AMOUNT {
                return Err("Airdrop amount exceeds testnet maximum (50 TRTH)".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let genesis_hash_hex = hex::encode(genesis_hash);
            if genesis_hash[0..4] != [0, 0, 0, 0] {
                return Err("Airdrop is only available on testnet".into());
            }

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let nonce: u64 = rand::random();

            let mut msg = Vec::new();
            msg.extend_from_slice(&genesis_hash);
            msg.extend_from_slice(&sender_account_id);
            msg.extend_from_slice(&sender_pubkey);
            msg.extend_from_slice(&amount_raw.to_le_bytes());
            msg.extend_from_slice(&timestamp.to_le_bytes());
            msg.extend_from_slice(&nonce.to_le_bytes());

            let signature = sender_keys.dilithium_sk.try_sign(&msg, b"truthlinked-airdrop-v1")?;

            let base = "https://airdrop.truthlinked.org";
            let req = serde_json::json!({
                "account_id": hex::encode(&sender_account_id),
                "pubkey": hex::encode(&sender_pubkey),
                "amount": amount_raw.to_string(),
                "amount_trth": amount,
                "timestamp": timestamp,
                "nonce": nonce,
                "chain_id": genesis_hash_hex,
                "signature": hex::encode(&signature),
            });

            let res = client.post(format!("{}/airdrop", base))
                .json(&req)
                .send()?;
            let status = res.status();
            let body = res.text()?;
            let parsed: Value = serde_json::from_str(&body)
                .map_err(|_| format!("Non-JSON response (status {}): {}", status, body))?;
            print_json(&parsed, cli.output)?;
        }
        
        Commands::Transfer { from, to_pubkey, amount } => {
            // Load sender keys
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            // Parse recipient pubkey
            let recipient_pk = hex::decode(&to_pubkey)?;
            if recipient_pk.len() != 1952 {
                return Err("Recipient pubkey must be 1952 bytes (Dilithium, 3904 hex chars)".into());
            }
            if amount == 0 {
                return Err("Amount must be > 0".into());
            }
            let recipient_id = pq_identity::account_id_from_pubkey(&recipient_pk);

            // Get genesis hash
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            // Create transaction
            let amount_raw = (amount as u128) * truthlinked::ONE_TRTH;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::Transfer {
                    recipient: recipient_id,
                    recipient_pubkey: recipient_pk.clone(),
                    amount: amount_raw,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            
            // Sign transaction
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            
            // Submit transaction using postcard encoding
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        Commands::PurchaseCU { from, trth_amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if trth_amount == 0 {
                return Err("trth_amount must be > 0".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let trth_amount_raw = (trth_amount as u128) * truthlinked::ONE_TRTH;

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::PurchaseCU {
                    trth_amount: trth_amount_raw,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = client
                .post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?
                .json()?;

            print_json(&res, cli.output)?;
        }
        Commands::BatchTransfer { from, to_pubkeys, amounts } => {
            // Load sender keys once
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            // Parse recipients and amounts (support decimals)
            let recipients: Vec<&str> = to_pubkeys.split(',').map(|s| s.trim()).collect();
            let amounts_vec: Vec<u128> = amounts.split(',')
                .map(|s| {
                    let s = s.trim();
                    if s.contains('.') {
                        let val: f64 = s.parse()?;
                        Ok((val * 1_000_000_000.0) as u128)
                    } else {
                        let val: u64 = s.parse()?;
                        Ok((val as u128) * truthlinked::ONE_TRTH)
                    }
                })
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
            
            if recipients.len() != amounts_vec.len() {
                return Err("Number of recipients must match number of amounts".into());
            }

            if recipients.is_empty() {
                return Err("No recipients provided".into());
            }
            if recipients.len() > constants::MAX_BATCH_TRANSFER_RECIPIENTS {
                return Err(format!(
                    "Too many recipients: {} (max: {})",
                    recipients.len(),
                    constants::MAX_BATCH_TRANSFER_RECIPIENTS
                ).into());
            }
            
            eprintln!(" Batch transfer: {} transactions", recipients.len());
            
            let balance_res: Value = client.post(format!("{}/balance", cli.rpc))
                .json(&serde_json::json!({"account_id": hex::encode(&sender_account_id)}))
                .send()?.json()?;

            let sender_balance: u128 = balance_res["balance"]
                .as_str()
                .and_then(|v| v.parse::<u128>().ok())
                .unwrap_or(0);

            let mut transfers = Vec::with_capacity(recipients.len());
            let mut total_amount: u128 = 0;
            for (i, (recipient_hex, amount)) in recipients.iter().zip(amounts_vec.iter()).enumerate() {
                if *amount == 0 {
                    return Err(format!("Amount at index {} must be > 0", i).into());
                }
                let recipient_pk = hex::decode(recipient_hex)?;
                if recipient_pk.len() != 1952 {
                    return Err(format!("Recipient pubkey at index {} must be 1952 bytes (3904 hex chars)", i).into());
                }
                let recipient_id = pq_identity::account_id_from_pubkey(&recipient_pk);
                total_amount = total_amount.saturating_add(*amount);
                transfers.push(pq_execution::BatchTransferEntry {
                    recipient: recipient_id,
                    recipient_pubkey: recipient_pk,
                    amount: *amount,
                });
            }

            let est_gas = (recipients.len() as u128) * (truthlinked::constants::GAS_TRANSFER as u128);
            let est_total = total_amount.saturating_add(est_gas);
            if sender_balance < est_total {
                return Err(format!(
                    "Insufficient balance for batch transfer: need {}, have {}",
                    est_total, sender_balance
                ).into());
            }
            
            // Get genesis hash once
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::BatchTransfer { transfers },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("Submitting batch transfer...");
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }
        Commands::ValidatorSetup { keys, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&keys)?;
            
            eprintln!(" Bonding {} TRTH...", amount);
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let amount_raw = (amount as u128) * truthlinked::ONE_TRTH;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;
            let calldata = encode_staking_stake(&sender_pubkey, amount_u64)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            if res.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                let tx_hash = res.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("unknown");
                eprintln!(" Bonded {} TRTH", amount);
                eprintln!("   TX Hash: {}", tx_hash);
                eprintln!("\n Validator setup complete!");
                eprintln!("   Status: Active");
                eprintln!("   Stake: {} TRTH", amount);
            } else {
                eprintln!(" Bonding failed: {}", json_string(&res, cli.output)?);
            }
        }
        Commands::Bond { from, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let amount_raw = (amount as u128) * truthlinked::ONE_TRTH;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;
            let calldata = encode_staking_stake(&sender_pubkey, amount_u64)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        Commands::Unbond { from, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let amount_raw = (amount as u128) * truthlinked::ONE_TRTH;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;
            let calldata = encode_staking_unstake(&sender_pubkey, amount_u64)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        Commands::Withdraw { from } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let calldata = encode_staking_withdraw(&sender_pubkey)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::Unjail { from } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let calldata = encode_staking_unjail(&sender_pubkey)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }

        Commands::DelegateAdd { from, delegate_pubkey } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let delegate_bytes = hex::decode(&delegate_pubkey)?;
            if delegate_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("delegate_pubkey must be 1952 bytes".into());
            }
            let delegate_account = pq_identity::account_id_from_pubkey(&delegate_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_delegate_add(delegate_account);
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::DelegateRemove { from, delegate_pubkey } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let delegate_bytes = hex::decode(&delegate_pubkey)?;
            if delegate_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("delegate_pubkey must be 1952 bytes".into());
            }
            let delegate_account = pq_identity::account_id_from_pubkey(&delegate_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_delegate_remove(delegate_account);
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::StakeFor { from, owner_pubkey, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let amount_raw = (amount as u128) * truthlinked::ONE_TRTH;
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_stake_for(owner_account, &owner_pubkey_bytes, amount_u64)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::UnstakeFor { from, owner_pubkey, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let amount_raw = (amount as u128) * truthlinked::ONE_TRTH;
            let amount_u64 = u64::try_from(amount_raw).map_err(|_| "Amount too large")?;

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_unstake_for(owner_account, &owner_pubkey_bytes, amount_u64)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::WithdrawFor { from, owner_pubkey } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_withdraw_for(owner_account, &owner_pubkey_bytes)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::UnjailFor { from, owner_pubkey } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let owner_pubkey_bytes = hex::decode(&owner_pubkey)?;
            if owner_pubkey_bytes.len() != VALIDATOR_PUBKEY_LEN {
                return Err("owner_pubkey must be 1952 bytes".into());
            }
            let owner_account = pq_identity::account_id_from_pubkey(&owner_pubkey_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_staking_unjail_for(owner_account, &owner_pubkey_bytes)?;
            let cell_id = truthlinked::pq_execution::staking_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::VetrthLock { from, amount, lock_blocks } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let owner = sender_account_id;

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let amount_raw = (amount as u128)
                .checked_mul(truthlinked::ONE_TRTH)
                .ok_or("amount too large")?;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }
            let calldata = encode_vetrth_lock(owner, lock_blocks);
            let cell_id = truthlinked::pq_execution::vetrth_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: amount_raw,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::VetrthExtend { from, lock_blocks } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let owner = sender_account_id;

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_vetrth_extend(owner, lock_blocks);
            let cell_id = truthlinked::pq_execution::vetrth_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::VetrthUnlock { from } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            let owner = sender_account_id;

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_vetrth_unlock(owner);
            let cell_id = truthlinked::pq_execution::vetrth_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            print_json(&res, cli.output)?;
        }

        Commands::TreasuryProposeSpend { from, bucket, recipient, amount, timelock_blocks, proposal_id } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let recipient_id = parse_account_id_hex(&recipient)?;
            let bucket_id = match bucket {
                TreasuryBucket::Community => 1u64,
                TreasuryBucket::Treasury => 2u64,
                TreasuryBucket::Validators => 3u64,
                TreasuryBucket::Strategic => 4u64,
            };

            let proposal_id = if let Some(hex_val) = proposal_id {
                parse_account_id_hex(&hex_val)?
            } else {
                let mut id = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut id);
                id
            };

            let amount_raw = (amount as u128)
                .checked_mul(truthlinked::ONE_TRTH)
                .ok_or("amount too large")?;
            if amount_raw == 0 {
                return Err("Amount must be > 0".into());
            }

            let calldata = encode_treasury_propose(
                proposal_id,
                bucket_id,
                recipient_id,
                amount_raw,
                timelock_blocks,
            );
            let cell_id = truthlinked::pq_execution::treasury_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            if cli.output == OutputFormat::Pretty {
                eprintln!("   Proposal ID: {}", hex::encode(proposal_id));
            }
            print_json(&res, cli.output)?;
        }

        Commands::TreasuryVoteSpend { from, proposal_id, approve } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let proposal_id = parse_account_id_hex(&proposal_id)?;
            let calldata = encode_treasury_vote(proposal_id, approve);
            let cell_id = truthlinked::pq_execution::treasury_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::TreasuryExecuteSpend { from, proposal_id } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let proposal_id = parse_account_id_hex(&proposal_id)?;
            let calldata = encode_treasury_execute(proposal_id);
            let cell_id = truthlinked::pq_execution::treasury_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::TreasuryProposalInfo { proposal_id } => {
            let _ = parse_account_id_hex(&proposal_id)?;
            let res: Value = client
                .get(format!("{}/treasury_proposal/{}", cli.rpc, proposal_id))
                .send()?
                .json()?;
            print_json(&res, cli.output)?;
        }
        
        Commands::MintNft { from, nft_id, name, metadata_uri, collection, royalty_bps, royalty_recipient } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let nft_id_bytes = hex::decode(&nft_id)?;
            if nft_id_bytes.len() != 32 {
                return Err("nft_id must be 32 bytes (64 hex chars)".into());
            }
            let mut nft_id_arr = [0u8; 32];
            nft_id_arr.copy_from_slice(&nft_id_bytes);
            
            let collection_arr = if let Some(c) = &collection {
                let c_bytes = hex::decode(c)?;
                if c_bytes.len() != 32 {
                    return Err("collection must be 32 bytes (64 hex chars)".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&c_bytes);
                Some(arr)
            } else {
                None
            };
            
            let royalty_recipient_id = if let Some(r) = &royalty_recipient {
                let r_bytes = hex::decode(r)?;
                if r_bytes.len() != 32 {
                    return Err("royalty_recipient must be 32 bytes (64 hex chars)".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&r_bytes);
                Some(arr)
            } else {
                None
            };

            if royalty_bps > 10_000 {
                return Err("royalty_bps must be between 0 and 10000".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::MintNFT {
                    nft_id: nft_id_arr,
                    name,
                    metadata_uri,
                    collection: collection_arr,
                    royalty_bps,
                    royalty_recipient: royalty_recipient_id,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::TransferNft { from, nft_id, to_pubkey, sale_price } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let nft_id_bytes = hex::decode(&nft_id)?;
            if nft_id_bytes.len() != 32 {
                return Err("nft_id must be 32 bytes (64 hex chars)".into());
            }
            let mut nft_id_arr = [0u8; 32];
            nft_id_arr.copy_from_slice(&nft_id_bytes);
            
            if let Some(p) = sale_price {
                if p == 0 {
                    return Err("sale_price must be > 0".into());
                }
            }

            let recipient_pubkey = hex::decode(&to_pubkey)?;
            if recipient_pubkey.len() != 1952 {
                return Err("Recipient pubkey must be 1952 bytes (3904 hex chars)".into());
            }
            let recipient_account_id = pq_identity::account_id_from_pubkey(&recipient_pubkey);

            // Preflight: ensure sender owns or is approved for this NFT
            let nft_info: Value = client.get(format!("{}/nft/{}", cli.rpc, nft_id)).send()?.json()?;
            if !nft_info.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Err("NFT not found".into());
            }
            let owner = nft_info["nft"]["owner"].as_str().unwrap_or("");
            let approved = nft_info["nft"]["approved"].as_str().unwrap_or("");
            let sender_hex = hex::encode(&sender_account_id);
            if owner != sender_hex && approved != sender_hex {
                return Err("Sender is not owner or approved operator".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::TransferNFT {
                    nft_id: nft_id_arr,
                    recipient: recipient_account_id,
                    recipient_pubkey,
                    sale_price: sale_price.map(|p| p as u128),
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::BurnNft { from, nft_id } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let nft_id_bytes = hex::decode(&nft_id)?;
            if nft_id_bytes.len() != 32 {
                return Err("nft_id must be 32 bytes (64 hex chars)".into());
            }
            let mut nft_id_arr = [0u8; 32];
            nft_id_arr.copy_from_slice(&nft_id_bytes);

            // Preflight: ensure sender owns this NFT
            let nft_info: Value = client.get(format!("{}/nft/{}", cli.rpc, nft_id)).send()?.json()?;
            if !nft_info.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Err("NFT not found".into());
            }
            let owner = nft_info["nft"]["owner"].as_str().unwrap_or("");
            let sender_hex = hex::encode(&sender_account_id);
            if owner != sender_hex {
                return Err("Sender is not owner".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::BurnNFT {
                    nft_id: nft_id_arr,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::ApproveNft { from, nft_id, approved_pubkey } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let nft_id_bytes = hex::decode(&nft_id)?;
            if nft_id_bytes.len() != 32 {
                return Err("nft_id must be 32 bytes (64 hex chars)".into());
            }
            let mut nft_id_arr = [0u8; 32];
            nft_id_arr.copy_from_slice(&nft_id_bytes);
            
            let approved_id = if let Some(pk) = approved_pubkey {
                let pk_bytes = hex::decode(&pk)?;
                if pk_bytes.len() != 1952 {
                    return Err("approved_pubkey must be 1952 bytes (3904 hex chars)".into());
                }
                let id = pq_identity::account_id_from_pubkey(&pk_bytes);
                Some(id)
            } else {
                None
            };

            // Preflight: ensure sender owns this NFT
            let nft_info: Value = client.get(format!("{}/nft/{}", cli.rpc, nft_id)).send()?.json()?;
            if !nft_info.get("found").and_then(|v| v.as_bool()).unwrap_or(false) {
                return Err("NFT not found".into());
            }
            let owner = nft_info["nft"]["owner"].as_str().unwrap_or("");
            let sender_hex = hex::encode(&sender_account_id);
            if owner != sender_hex {
                return Err("Sender is not owner".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ApproveNFT {
                    nft_id: nft_id_arr,
                    approved: approved_id,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::GetNft { nft_id } => {
            let nft_id_bytes = hex::decode(&nft_id)?;
            if nft_id_bytes.len() != 32 {
                return Err("nft_id must be 32 bytes (64 hex chars)".into());
            }
            
            let res: Value = client.get(format!("{}/nft/{}", cli.rpc, nft_id)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        
        Commands::MyNfts { account } => {
            // Get account ID from keyfile or use directly
            let account_id = if account.ends_with(".json") {
                let keys = pq_identity::DualKeypair::load(&account)?;
                let pk = keys.dilithium_pk.into_bytes();
                pq_identity::account_id_from_pubkey(&pk)
            } else {
                let bytes = hex::decode(&account)?;
                if bytes.len() != 32 {
                    return Err("account must be 32 bytes (64 hex chars)".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            };
            
            let account_hex = hex::encode(&account_id);
            
            // Query NFTs owned by this account
            let res: Value = client.get(format!("{}/nfts/{}", cli.rpc, account_hex)).send()?.json()?;
            print_json(&res, cli.output)?;
        }
        
        Commands::DeployCell { from, cell_id, source, bytecode_file, initial_balance, manifest_file } => {
            let (wasm_path, manifest_path) = if let Some(src) = source {
            eprintln!(" Auto-building from source...");
                let (wasm, manifest) = build_cell(&src, None)?;
                (wasm, Some(manifest))
            } else if let Some(wasm) = bytecode_file {
                let manifest = manifest_file.or_else(|| {
                    let auto_manifest_path = wasm.replace(".wasm", ".manifest.json");
                    if std::path::Path::new(&auto_manifest_path).exists() {
                        eprintln!(" Found manifest: {}", auto_manifest_path);
                        Some(auto_manifest_path)
                    } else {
                        None
                    }
                });
                (wasm, manifest)
            } else {
                return Err("Must provide either --source or --bytecode-file".into());
            };

            submit_cell_deploy(
                &client,
                &cli.rpc,
                &from,
                &cell_id,
                &wasm_path,
                manifest_path,
                initial_balance,
                cli.output,
            )?;
        }
        
        Commands::DeployToken { from, cell_id, name, symbol, decimals, supply } => {
            let sender_keys = DualKeypair::load(&from)?;
            let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
            let sender_account_id = truthlinked::pq_identity::account_id_from_pubkey(&pubkey);
            
            let cell_id_bytes = hex::decode(&cell_id)?;
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = Transaction {
                sender: sender_account_id,
                intent: TransactionIntent::DeployToken {
                    cell_id: cell_id_arr,
                    name,
                    symbol,
                    decimals,
                    total_supply: supply,
                    transfer_fee_bps: 0,
                    transfer_fee_recipient: None,
                    non_transferable: false,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            eprintln!("Submitting token deployment...");
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::CallCell { from, cell_id, calldata, value, gas_limit, simulate } => {
            let sender_keys = DualKeypair::load(&from)?;
            let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
            let sender_account_id = truthlinked::pq_identity::account_id_from_pubkey(&pubkey);
            
            let cell_id_bytes = hex::decode(&cell_id)?;
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);
            
            let calldata_bytes = hex::decode(&calldata)?;
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = Transaction {
                sender: sender_account_id,
                intent: TransactionIntent::CallCell {
                    cell_id: cell_id_arr,
                    calldata: calldata_bytes,
                    value: value as u128,
                    gas_limit,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let endpoint = if simulate { "simulate_raw" } else { "submit_raw" };
            if simulate {
                eprintln!("Simulating cell call...");
                eprintln!(" NOTE: simulation signs and sends the transaction for validation only; no state is committed.");
            } else {
                eprintln!("Calling cell...");
            }
            let res: Value = client.post(format!("{}/{}", cli.rpc, endpoint))
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::UpgradeCell { from, cell_id, source, bytecode_file, manifest_file } => {
            // Auto-build if source provided
            let (wasm_path, manifest_path) = if let Some(src) = source {
                eprintln!(" Auto-building from source...");
                let (wasm, manifest) = build_cell(&src, None)?;
                (wasm, Some(manifest))
            } else if let Some(wasm) = bytecode_file {
                // Use provided bytecode
                let manifest = manifest_file.or_else(|| {
                    let auto_manifest = wasm.replace(".wasm", ".manifest.json");
                    if std::path::Path::new(&auto_manifest).exists() {
                        eprintln!(" Found manifest: {}", auto_manifest);
                        Some(auto_manifest)
                    } else {
                        None
                    }
                });
                (wasm, manifest)
            } else {
                return Err("Must provide either --source or --bytecode-file".into());
            };
            
            let sender_keys = DualKeypair::load(&from)?;
            let pubkey = sender_keys.dilithium_pk.clone().into_bytes();
            let sender_account_id = truthlinked::pq_identity::account_id_from_pubkey(&pubkey);
            
            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);
            
            let new_bytecode = std::fs::read(&wasm_path)?;
            
            // Load manifest if available
            let (new_declared_reads, new_declared_writes, new_commutative_keys, new_storage_key_specs) = if let Some(manifest_path) = manifest_path {
                let (new_declared_reads, new_declared_writes, new_commutative_keys, new_storage_key_specs) =
                    load_manifest_sets(&manifest_path)?;
                
                // Verify manifest locally
                truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                    &new_bytecode,
                    &new_declared_reads,
                    &new_declared_writes,
                    &new_storage_key_specs,
                )?;
                
                eprintln!(" Manifest verified locally");
                (new_declared_reads, new_declared_writes, new_commutative_keys, new_storage_key_specs)
            } else if let Ok(Some(manifest_json)) = extract_manifest_section(&new_bytecode) {
                let (new_declared_reads, new_declared_writes, new_commutative_keys, new_storage_key_specs) =
                    load_manifest_sets_from_json(&manifest_json)?;
                truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                    &new_bytecode,
                    &new_declared_reads,
                    &new_declared_writes,
                    &new_storage_key_specs,
                )?;
                eprintln!(" Manifest extracted from WASM and verified locally.");
                (new_declared_reads, new_declared_writes, new_commutative_keys, new_storage_key_specs)
            } else {
                return Err("No manifest found for upgrade. Provide --manifest-file or embed it via SDK build.".into());
            };
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = Transaction {
                sender: sender_account_id,
                intent: TransactionIntent::UpgradeCell {
                    cell_id: cell_id_arr,
                    new_bytecode,
                    new_declared_reads,
                    new_declared_writes,
                    new_commutative_keys,
                    new_storage_key_specs,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            eprintln!("Upgrading cell...");
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::RotateKey { from, new_pubkey } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let new_pubkey_bytes = hex::decode(&new_pubkey)?;
            if new_pubkey_bytes.len() != 1952 {
                return Err("new_pubkey must be 1952 bytes (3904 hex chars)".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::RotateKey {
                    new_pubkey: new_pubkey_bytes,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::AcceptOwnership { from, cell_id } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::AcceptOwnership {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::MakeImmutable { from, cell_id } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let cell_info = require_cell_exists(&client, &cli.rpc, &cell_id)?;
            if cell_info.immutable {
                return Err("cell is already immutable".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::MakeImmutable {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }

        Commands::CloseCell { from, cell_id } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let cell_info = require_cell_exists(&client, &cli.rpc, &cell_id)?;
            if cell_info.immutable {
                return Err("cell is immutable".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CloseCell {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::ProposeCellUpgrade { from, cell_id, source, bytecode_file, manifest_file, timelock_blocks } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let (wasm_path, manifest_path) = if let Some(src) = source {
                eprintln!(" Auto-building from source...");
                let (wasm, manifest) = build_cell(&src, None)?;
                (wasm, Some(manifest))
            } else if let Some(wasm) = bytecode_file {
                let manifest = manifest_file.or_else(|| {
                    let auto_manifest = wasm.replace(".wasm", ".manifest.json");
                    if std::path::Path::new(&auto_manifest).exists() {
                        eprintln!(" Found manifest: {}", auto_manifest);
                        Some(auto_manifest)
                    } else {
                        None
                    }
                });
                (wasm, manifest)
            } else {
                return Err("Must provide either --source or --bytecode-file".into());
            };

            let new_bytecode = std::fs::read(&wasm_path)?;
            let (declared_reads, declared_writes, commutative_keys, storage_key_specs) = if let Some(manifest_path) = manifest_path {
                let (reads, writes, commutative, specs) = load_manifest_sets(&manifest_path)?;
                truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                    &new_bytecode,
                    &reads,
                    &writes,
                    &specs,
                )?;
                (reads, writes, commutative, specs)
            } else if let Ok(Some(manifest_json)) = extract_manifest_section(&new_bytecode) {
                let (reads, writes, commutative, specs) = load_manifest_sets_from_json(&manifest_json)?;
                truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                    &new_bytecode,
                    &reads,
                    &writes,
                    &specs,
                )?;
                (reads, writes, commutative, specs)
            } else {
                return Err("No manifest found for proposal. Provide --manifest-file or embed it via SDK build.".into());
            };

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ProposeCellUpgrade {
                    cell_id: cell_id_arr,
                    new_bytecode,
                    new_declared_reads: declared_reads,
                    new_declared_writes: declared_writes,
                    new_commutative_keys: commutative_keys,
                    new_storage_key_specs: storage_key_specs,
                    timelock_blocks,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::ProposeCellOwnershipTransfer { from, cell_id, new_owner, timelock_blocks } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let new_owner_bytes = hex::decode(&new_owner)?;
            if new_owner_bytes.len() != 32 {
                return Err("new_owner must be 32 bytes (64 hex chars)".into());
            }
            let mut new_owner_arr = [0u8; 32];
            new_owner_arr.copy_from_slice(&new_owner_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ProposeCellOwnershipTransfer {
                    cell_id: cell_id_arr,
                    new_owner: new_owner_arr,
                    timelock_blocks,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::ProposeCellMakeImmutable { from, cell_id, timelock_blocks } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ProposeCellMakeImmutable {
                    cell_id: cell_id_arr,
                    timelock_blocks,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::VoteCellProposal { from, cell_id, approve } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::VoteCellProposal {
                    cell_id: cell_id_arr,
                    approve,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::ExecuteCellProposal { from, cell_id } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32 bytes (64 hex chars)".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::ExecuteCellProposal {
                    cell_id: cell_id_arr,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }
        
        Commands::TokenTransfer { from, token, to, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            if amount == 0 {
                return Err("amount must be > 0".into());
            }
            
            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);
            
            let to_bytes = hex::decode(&to)?;
            if to_bytes.len() != 32 {
                return Err("to must be 32 bytes (64 hex chars)".into());
            }
            let mut to_arr = [0u8; 32];
            to_arr.copy_from_slice(&to_bytes);

            require_token_cell(&client, &cli.rpc, &token)?;
            require_account_exists(&client, &cli.rpc, &to)?;
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::TokenTransfer {
                    token_cell: token_arr,
                    recipient: to_arr,
                    amount,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::TokenMint { from, token, to, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            if amount == 0 {
                return Err("amount must be > 0".into());
            }
            
            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);
            
            let to_bytes = hex::decode(&to)?;
            if to_bytes.len() != 32 {
                return Err("to must be 32 bytes (64 hex chars)".into());
            }
            let mut to_arr = [0u8; 32];
            to_arr.copy_from_slice(&to_bytes);

            require_token_cell(&client, &cli.rpc, &token)?;
            require_account_exists(&client, &cli.rpc, &to)?;
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::TokenMint {
                    token_cell: token_arr,
                    recipient: to_arr,
                    amount,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::TokenBurn { from, token, amount } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            if amount == 0 {
                return Err("amount must be > 0".into());
            }
            
            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            require_token_cell(&client, &cli.rpc, &token)?;
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::TokenBurn {
                    token_cell: token_arr,
                    amount,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }

        Commands::ProposeTokenAuthority {
            from,
            token,
            mint_authority,
            clear_mint_authority,
            freeze_authority,
            clear_freeze_authority,
            voting_period_blocks,
        } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if mint_authority.is_some() && clear_mint_authority {
                return Err("Cannot set and clear mint authority at the same time".into());
            }
            if freeze_authority.is_some() && clear_freeze_authority {
                return Err("Cannot set and clear freeze authority at the same time".into());
            }
            let set_mint_authority = mint_authority.is_some() || clear_mint_authority;
            let set_freeze_authority = freeze_authority.is_some() || clear_freeze_authority;
            if !set_mint_authority && !set_freeze_authority {
                return Err("Must set at least one authority (mint or freeze)".into());
            }

            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            let new_mint_authority = if let Some(hex_val) = mint_authority {
                let bytes = hex::decode(&hex_val)?;
                if bytes.len() != 32 {
                    return Err("mint_authority must be 32 bytes (64 hex chars)".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else if clear_mint_authority {
                None
            } else {
                None
            };

            let new_freeze_authority = if let Some(hex_val) = freeze_authority {
                let bytes = hex::decode(&hex_val)?;
                if bytes.len() != 32 {
                    return Err("freeze_authority must be 32 bytes (64 hex chars)".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else if clear_freeze_authority {
                None
            } else {
                None
            };

            require_token_cell(&client, &cli.rpc, &token)?;
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let mint_arr = new_mint_authority.unwrap_or([0u8; 32]);
            let freeze_arr = new_freeze_authority.unwrap_or([0u8; 32]);
            let calldata = encode_token_authority_propose(
                token_arr,
                set_mint_authority,
                mint_arr,
                set_freeze_authority,
                freeze_arr,
                voting_period_blocks,
            );
            let cell_id = truthlinked::pq_execution::token_governance_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }

        Commands::VoteTokenAuthority { from, token, approve } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let token_bytes = hex::decode(&token)?;
            if token_bytes.len() != 32 {
                return Err("token must be 32 bytes (64 hex chars)".into());
            }
            let mut token_arr = [0u8; 32];
            token_arr.copy_from_slice(&token_bytes);

            require_token_cell(&client, &cli.rpc, &token)?;
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_token_authority_vote(token_arr, approve);
            let cell_id = truthlinked::pq_execution::token_governance_system_cell_id();

            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;

            print_json(&res, cli.output)?;
        }
        
        Commands::CallChain { from, calls, gas_limit, simulate } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);
            
            let cell_calls = parse_call_chain_json(&calls)?;
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCellChain {
                    calls: cell_calls,
                    gas_limit,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
            expiration_height: u64::MAX,
            };
            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            let endpoint = if simulate { "simulate_raw" } else { "submit_raw" };
            if simulate {
                eprintln!("Simulating call chain...");
                eprintln!(" NOTE: simulation signs and sends the transaction for validation only; no state is committed.");
            } else {
                eprintln!("Submitting call chain...");
            }
            let res: Value = client.post(format!("{}/{}", cli.rpc, endpoint))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::ProposeName { from, name, target, owner } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }
            
            let target_bytes = hex::decode(&target)?;
            if target_bytes.len() != 32 {
                return Err("target must be 32 bytes (64 hex chars)".into());
            }
            let mut target_arr = [0u8; 32];
            target_arr.copy_from_slice(&target_bytes);
            
            let owner_bytes = hex::decode(&owner)?;
            if owner_bytes.len() != 32 {
                return Err("owner must be 32 bytes (64 hex chars)".into());
            }
            let mut owner_arr = [0u8; 32];
            owner_arr.copy_from_slice(&owner_bytes);
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_propose(&name, target_arr, owner_arr)?;
            let cell_id = truthlinked::pq_execution::name_registry_system_cell_id();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::VoteName { from, name, approve } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_vote(&name, approve)?;
            let cell_id = truthlinked::pq_execution::name_registry_system_cell_id();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::RenewName { from, name } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_renew(&name)?;
            let cell_id = truthlinked::pq_execution::name_registry_system_cell_id();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }
        
        Commands::TransferName { from, name, new_owner } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if name.trim().is_empty() {
                return Err("name must not be empty".into());
            }
            
            let new_owner_bytes = hex::decode(&new_owner)?;
            if new_owner_bytes.len() != 32 {
                return Err("new_owner must be 32 bytes (64 hex chars)".into());
            }
            let mut new_owner_arr = [0u8; 32];
            new_owner_arr.copy_from_slice(&new_owner_bytes);
            
            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;
            
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let calldata = encode_name_registry_transfer(&name, new_owner_arr)?;
            let cell_id = truthlinked::pq_execution::name_registry_system_cell_id();
            
            let tx = pq_execution::Transaction {
                sender: sender_account_id,
                intent: pq_execution::TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;
            
            let res: Value = client.post(format!("{}/submit_raw", cli.rpc))
                .header("Content-Type", "application/octet-stream")
                .body(tx_bytes)
                .send()?.json()?;
            
            print_json(&res, cli.output)?;
        }

        Commands::ProposeUrl { from, url_pattern, bond, voting_period_blocks } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if url_pattern.trim().is_empty() {
                return Err("url_pattern must not be empty".into());
            }
            if bond == 0 {
                return Err("bond must be > 0".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let bond_amount = (bond as u128)
                .checked_mul(truthlinked::ONE_TRTH)
                .ok_or("Bond overflow")?;

            let calldata = encode_oracle_propose_url(&url_pattern, bond_amount, voting_period_blocks)?;
            let cell_id = truthlinked::pq_execution::oracle_governance_system_cell_id();

            let tx = Transaction {
                sender: sender_account_id,
                intent: TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("Submitting URL proposal...");
            let res: Value = client
                .post(format!("{}/submit_raw", cli.rpc))
                .body(tx_bytes)
                .send()?
                .json()?;

            print_json(&res, cli.output)?;
        }

        Commands::VoteUrl { from, url_pattern, approve } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if url_pattern.trim().is_empty() {
                return Err("url_pattern must not be empty".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_oracle_vote_url(&url_pattern, approve)?;
            let cell_id = truthlinked::pq_execution::oracle_governance_system_cell_id();

            let tx = Transaction {
                sender: sender_account_id,
                intent: TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("Submitting URL vote...");
            let res: Value = client
                .post(format!("{}/submit_raw", cli.rpc))
                .body(tx_bytes)
                .send()?
                .json()?;

            print_json(&res, cli.output)?;
        }

        Commands::ReportMaliciousUrl { from, url_pattern, evidence } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            if url_pattern.trim().is_empty() {
                return Err("url_pattern must not be empty".into());
            }
            if evidence.trim().is_empty() {
                return Err("evidence must not be empty".into());
            }

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

            let calldata = encode_oracle_report_malicious(&url_pattern, &evidence)?;
            let cell_id = truthlinked::pq_execution::oracle_governance_system_cell_id();

            let tx = Transaction {
                sender: sender_account_id,
                intent: TransactionIntent::CallCell {
                    cell_id,
                    calldata,
                    value: 0,
                    gas_limit: SYSTEM_CONTROLLER_GAS_LIMIT,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("Submitting malicious URL report...");
            let res: Value = client
                .post(format!("{}/submit_raw", cli.rpc))
                .body(tx_bytes)
                .send()?
                .json()?;

            print_json(&res, cli.output)?;
        }

        Commands::UpgradeVisibility { from, cell_id, public } => {
            let sender_keys = pq_identity::DualKeypair::load(&from)?;
            let sender_pubkey = sender_keys.dilithium_pk.clone().into_bytes().to_vec();
            let sender_account_id = pq_identity::account_id_from_pubkey(&sender_pubkey);

            let cell_id_bytes = hex::decode(&cell_id)?;
            if cell_id_bytes.len() != 32 {
                return Err("cell_id must be 32-byte hex".into());
            }
            let mut cell_id_arr = [0u8; 32];
            cell_id_arr.copy_from_slice(&cell_id_bytes);

            require_cell_exists(&client, &cli.rpc, &cell_id)?;

            let genesis_hash = fetch_genesis_hash(&client, &cli.rpc)?;

            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            let visibility = if public { 1 } else { 0 };

            let tx = Transaction {
                sender: sender_account_id,
                intent: TransactionIntent::SetCellVisibility {
                    cell_id: cell_id_arr,
                    visibility,
                },
                signature: vec![],
                timestamp,
                chain_id: genesis_hash,
                expiration_height: u64::MAX,
            };

            let signed_tx = sender_keys.sign_transaction(&tx)?;
            let tx_bytes = postcard::to_allocvec(&signed_tx)?;

            eprintln!("Submitting visibility upgrade...");
            let res: Value = client
                .post(format!("{}/submit_raw", cli.rpc))
                .body(tx_bytes)
                .send()?
                .json()?;

            print_json(&res, cli.output)?;
        }
        
        // Manifest SDK commands (local, no rpc)
        Commands::Build { source, output } => {
            build_cell(&source, output.as_deref())?;
        }

        Commands::SdkNew { path } => {
            let target_dir = std::path::Path::new(&path);
            if target_dir.exists() {
                return Err(format!("Target path already exists: {}", path).into());
            }
            std::fs::create_dir_all(target_dir)?;
            write_embedded_dir(&SDK_TEMPLATE_DIR, target_dir)?;
            println!(" SDK cell template created at {}", path);
            println!("   Dependency: truthlinked-sdk = \"0.1.0\"");
            println!("   Next: cd {} && cargo build --release --target truthlinked-cells", path);
        }

        Commands::SdkBuild { path, output } => {
            let (wasm_path, manifest_path) = sdk_build_project(&path, output.as_deref())?;
            println!(" SDK build complete");
            println!("   WASM: {}", wasm_path);
            println!("   Manifest: {}", manifest_path);
        }

        Commands::SdkDeploy {
            from,
            cell_id,
            path,
            bytecode_file,
            initial_balance,
            manifest_file,
            skip_build,
        } => {
            let (wasm_path, built_manifest_path) = if let Some(wasm) = bytecode_file {
                (wasm, None)
            } else if skip_build {
                (sdk_locate_wasm(&path)?, None)
            } else {
                let (wasm, manifest) = sdk_build_project(&path, None)?;
                (wasm, Some(manifest))
            };

            let manifest_path =
                resolve_manifest_path(&wasm_path, manifest_file.or(built_manifest_path));

            submit_cell_deploy(
                &client,
                &cli.rpc,
                &from,
                &cell_id,
                &wasm_path,
                manifest_path,
                initial_balance,
                cli.output,
            )?;
        }

        Commands::ManifestInit { bytecode_file } => {
            let bytecode = std::fs::read(&bytecode_file)?;
            let analysis = truthlinked::cells::CellAccount::analyze_bytecode(&bytecode)?;

            // Auto-populate slot lists from static analysis.
            let reads_json: Vec<serde_json::Value> = analysis
                .static_read_slots
                .iter()
                .map(|s| serde_json::Value::String(hex::encode(s)))
                .collect();
            let writes_json: Vec<serde_json::Value> = analysis
                .static_write_slots
                .iter()
                .map(|s| serde_json::Value::String(hex::encode(s)))
                .collect();

            let resolution_note = if !analysis.has_storage_reads && !analysis.has_storage_writes {
                "No storage operations detected. Empty manifest is valid."
            } else if analysis.fully_resolved {
                "All storage slot addresses resolved from bytecode data section. Manifest is complete."
            } else {
                "PARTIAL: some storage calls use dynamic slot addresses that cannot be resolved statically. \
                 Review and complete declared_reads/declared_writes manually, \
                 or use the TruthLinked Rust SDK (storage_slot! macro) for full static resolution."
            };

            let manifest = serde_json::json!({
                "declared_reads":   reads_json,
                "declared_writes":  writes_json,
                "commutative_keys": [],
                "storage_key_specs": [],
                "_resolution": resolution_note,
                "_static_analysis": {
                    "has_storage_reads":    analysis.has_storage_reads,
                    "has_storage_writes":   analysis.has_storage_writes,
                    "fully_resolved":       analysis.fully_resolved,
                    "resolved_read_count":  analysis.static_read_slots.len(),
                    "resolved_write_count": analysis.static_write_slots.len(),
                }
            });

            let manifest_path = bytecode_file.replace(".wasm", ".manifest.json");
            std::fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;

            println!("Manifest written: {}", manifest_path);
            if analysis.fully_resolved {
                println!("Static resolution: COMPLETE");
                println!("  Read slots  resolved: {}", analysis.static_read_slots.len());
                println!("  Write slots resolved: {}", analysis.static_write_slots.len());
            } else if analysis.has_storage_reads || analysis.has_storage_writes {
                println!("Static resolution: PARTIAL");
                println!("  Resolved reads:  {}", analysis.static_read_slots.len());
                println!("  Resolved writes: {}", analysis.static_write_slots.len());
                println!("  Action: fill remaining slots manually or use the SDK storage_slot! macro.");
            } else {
                println!("No storage operations. Manifest is complete.");
            }
        }
        
        Commands::ManifestVerify { bytecode_file, manifest_file } => {
            let bytecode = std::fs::read(&bytecode_file)?;
            let (declared_reads, declared_writes, _commutative_keys, storage_key_specs) =
                load_manifest_sets(&manifest_file)?;
            
            // Verify manifest against bytecode.
            match truthlinked::cells::CellAccount::verify_manifest_against_bytecode(
                &bytecode,
                &declared_reads,
                &declared_writes,
                &storage_key_specs,
            ) {
                Ok(()) => {
                    let analysis = truthlinked::cells::CellAccount::analyze_bytecode(&bytecode)?;
                    println!("Manifest verification PASSED");
                    println!("  Bytecode: {}", bytecode_file);
                    println!("  Manifest: {}", manifest_file);
                    println!("  Declared reads:  {}", declared_reads.len());
                    println!("  Declared writes: {}", declared_writes.len());
                    println!("  Key specs:       {}", storage_key_specs.len());
                    if analysis.fully_resolved {
                        println!("  Static analysis: FULL ({} read / {} write slots confirmed in bytecode)",
                            analysis.static_read_slots.len(),
                            analysis.static_write_slots.len());
                    } else if analysis.has_storage_reads || analysis.has_storage_writes {
                        println!("  Static analysis: PARTIAL — dynamic calls accepted on declared trust.");
                        println!("    Use the SDK storage_slot! macro to enable full bytecode enforcement.");
                    } else {
                        println!("  Static analysis: No storage operations detected.");
                    }
                }
                Err(e) => {
                    eprintln!("Manifest verification FAILED");
                    eprintln!("  Reason: {}", e);
                    std::process::exit(1);
                }
            }
        }
        
        Commands::ManifestHash { bytecode_file, manifest_file } => {
            let bytecode = std::fs::read(&bytecode_file)?;
            let (declared_reads, declared_writes, commutative_keys, _storage_key_specs) =
                load_manifest_sets(&manifest_file)?;
            
            let manifest_hash = truthlinked::cells::CellAccount::compute_manifest_hash(
                &bytecode,
                &declared_reads,
                &declared_writes,
                &commutative_keys,
            );
            
            println!(" Manifest Hash: {}", hex::encode(&manifest_hash));
            println!("   Bytecode: {}", bytecode_file);
            println!("   Manifest: {}", manifest_file);
            println!("   This hash will be stored on-chain at deploy/upgrade.");
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cmd(args: &[&str]) -> (OutputFormat, Commands) {
        let mut full = vec!["trth-cli"];
        full.extend_from_slice(args);
        let cli = Cli::parse_from(full);
        (cli.output, cli.command)
    }

    #[test]
    fn parse_package_name_uses_toml() {
        let tmp = std::env::temp_dir().join(format!(
            "trth_cli_pkg_{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let content = r#"
[package]
name = "my_cell"
version = "0.1.0"

[package.metadata]
name = "not_this_one"
"#;
        std::fs::write(&tmp, content).unwrap();
        let name = parse_package_name(&tmp).unwrap();
        assert_eq!(name, "my_cell");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn json_string_respects_output_format() {
        let value = serde_json::json!({"ok": true, "n": 1});
        let compact = json_string(&value, OutputFormat::Json).unwrap();
        let pretty = json_string(&value, OutputFormat::Pretty).unwrap();
        assert!(compact.contains("\"ok\":true"));
        assert!(pretty.contains("\n"));
    }

    #[test]
    fn call_chain_total_calldata_limit_enforced() {
        let max = constants::MAX_CALL_CHAIN_TOTAL_CALLDATA;
        let call1 = serde_json::json!({
            "cell": "00".repeat(32),
            "calldata": hex::encode(vec![0u8; max]),
            "value": 0
        });
        let call2 = serde_json::json!({
            "cell": "11".repeat(32),
            "calldata": "00",
            "value": 0
        });
        let calls = serde_json::json!([call1, call2]).to_string();
        let err = parse_call_chain_json(&calls).expect_err("should exceed total calldata");
        assert!(err.to_string().contains("total calldata"));
    }

    #[test]
    fn parse_output_format_flag() {
        let (output, cmd) = parse_cmd(&["--output", "json", "chain-info"]);
        assert!(matches!(output, OutputFormat::Json));
        assert!(matches!(cmd, Commands::ChainInfo));
    }

    #[test]
    fn parse_basic_queries() {
        assert!(matches!(parse_cmd(&["chain-info"]).1, Commands::ChainInfo));
        assert!(matches!(parse_cmd(&["token-info"]).1, Commands::TokenInfo));
        assert!(matches!(parse_cmd(&["network-info"]).1, Commands::NetworkInfo));
        assert!(matches!(parse_cmd(&["validators"]).1, Commands::Validators));
        assert!(matches!(parse_cmd(&["mempool"]).1, Commands::Mempool));
        assert!(matches!(parse_cmd(&["list-cell-proposals"]).1, Commands::ListCellProposals));
        assert!(matches!(
            parse_cmd(&["tx-status", "aa"]).1,
            Commands::TxStatus { .. }
        ));
        assert!(matches!(
            parse_cmd(&["balance", "aa"]).1,
            Commands::Balance { .. }
        ));
        assert!(matches!(
            parse_cmd(&["balance-by-pubkey", "bb"]).1,
            Commands::BalanceByPubkey { .. }
        ));
    }

    #[test]
    fn parse_identity_commands() {
        let cmd = parse_cmd(&["account-id", "--pubkey", "aa"]).1;
        assert!(matches!(cmd, Commands::AccountId { .. }));
        let cmd = parse_cmd(&["import-mnemonic", "--mnemonic", "word1 word2 word3"]).1;
        assert!(matches!(cmd, Commands::ImportMnemonic { .. }));
        let cmd = parse_cmd(&["account-create", "--encrypt"]).1;
        assert!(matches!(cmd, Commands::AccountCreate { .. }));
    }

    #[test]
    fn parse_transfer_commands() {
        let cmd = parse_cmd(&["transfer", "--from", "k", "--to-pubkey", "aa", "--amount", "1"]).1;
        assert!(matches!(cmd, Commands::Transfer { .. }));
        let cmd = parse_cmd(&["purchase-cu", "--from", "k", "--trth-amount", "1"]).1;
        assert!(matches!(cmd, Commands::PurchaseCU { .. }));
        let cmd = parse_cmd(&["batch-transfer", "--from", "k", "--to-pubkeys", "aa,bb", "--amounts", "1,2"]).1;
        assert!(matches!(cmd, Commands::BatchTransfer { .. }));
        let cmd = parse_cmd(&["airdrop", "--from", "k"]).1;
        assert!(matches!(cmd, Commands::Airdrop { .. }));
    }

    #[test]
    fn parse_staking_commands() {
        assert!(matches!(
            parse_cmd(&["validator-setup", "--keys", "k", "--amount", "10"]).1,
            Commands::ValidatorSetup { .. }
        ));
        assert!(matches!(
            parse_cmd(&["bond", "--from", "k", "--amount", "10"]).1,
            Commands::Bond { .. }
        ));
        assert!(matches!(
            parse_cmd(&["unbond", "--from", "k", "--amount", "10"]).1,
            Commands::Unbond { .. }
        ));
        assert!(matches!(
            parse_cmd(&["withdraw", "--from", "k"]).1,
            Commands::Withdraw { .. }
        ));
        assert!(matches!(
            parse_cmd(&["unjail", "--from", "k"]).1,
            Commands::Unjail { .. }
        ));
    }

    #[test]
    fn parse_nft_commands() {
        assert!(matches!(
            parse_cmd(&["mint-nft", "--from", "k", "--nft-id", "aa", "--name", "n", "--metadata-uri", "ipfs://x"]).1,
            Commands::MintNft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["transfer-nft", "--from", "k", "--nft-id", "aa", "--to-pubkey", "bb"]).1,
            Commands::TransferNft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["burn-nft", "--from", "k", "--nft-id", "aa"]).1,
            Commands::BurnNft { .. }
        ));
        assert!(matches!(
            parse_cmd(&["approve-nft", "--from", "k", "--nft-id", "aa"]).1,
            Commands::ApproveNft { .. }
        ));
    }

    #[test]
    fn parse_cell_commands() {
        assert!(matches!(
            parse_cmd(&["deploy-cell", "--from", "k", "--cell-id", "aa", "--source", "src/lib.rs"]).1,
            Commands::DeployCell { .. }
        ));
        assert!(matches!(
            parse_cmd(&["deploy-token", "--from", "k", "--cell-id", "aa", "--name", "T", "--symbol", "T", "--decimals", "9", "--supply", "100"]).1,
            Commands::DeployToken { .. }
        ));
        assert!(matches!(
            parse_cmd(&["call-cell", "--from", "k", "--cell-id", "aa", "--calldata", "00", "--simulate"]).1,
            Commands::CallCell { simulate: true, .. }
        ));
        assert!(matches!(
            parse_cmd(&["upgrade-cell", "--from", "k", "--cell-id", "aa", "--bytecode-file", "c.wasm"]).1,
            Commands::UpgradeCell { .. }
        ));
        assert!(matches!(
            parse_cmd(&["rotate-key", "--from", "k", "--new-pubkey", "aa"]).1,
            Commands::RotateKey { .. }
        ));
        assert!(matches!(
            parse_cmd(&["accept-ownership", "--from", "k", "--cell-id", "aa"]).1,
            Commands::AcceptOwnership { .. }
        ));
        assert!(matches!(
            parse_cmd(&["make-immutable", "--from", "k", "--cell-id", "aa"]).1,
            Commands::MakeImmutable { .. }
        ));
        assert!(matches!(
            parse_cmd(&["close-cell", "--from", "k", "--cell-id", "aa"]).1,
            Commands::CloseCell { .. }
        ));
        assert!(matches!(
            parse_cmd(&["propose-cell-upgrade", "--from", "k", "--cell-id", "aa", "--bytecode-file", "c.wasm"]).1,
            Commands::ProposeCellUpgrade { .. }
        ));
        assert!(matches!(
            parse_cmd(&["propose-cell-ownership-transfer", "--from", "k", "--cell-id", "aa", "--new-owner", "bb"]).1,
            Commands::ProposeCellOwnershipTransfer { .. }
        ));
        assert!(matches!(
            parse_cmd(&["propose-cell-make-immutable", "--from", "k", "--cell-id", "aa"]).1,
            Commands::ProposeCellMakeImmutable { .. }
        ));
        assert!(matches!(
            parse_cmd(&["vote-cell-proposal", "--from", "k", "--cell-id", "aa", "--approve"]).1,
            Commands::VoteCellProposal { .. }
        ));
        assert!(matches!(
            parse_cmd(&["execute-cell-proposal", "--from", "k", "--cell-id", "aa"]).1,
            Commands::ExecuteCellProposal { .. }
        ));
    }

    #[test]
    fn parse_token_commands() {
        assert!(matches!(
            parse_cmd(&["token-transfer", "--from", "k", "--token", "aa", "--to", "bb", "--amount", "1"]).1,
            Commands::TokenTransfer { .. }
        ));
        assert!(matches!(
            parse_cmd(&["token-mint", "--from", "k", "--token", "aa", "--to", "bb", "--amount", "1"]).1,
            Commands::TokenMint { .. }
        ));
        assert!(matches!(
            parse_cmd(&["token-burn", "--from", "k", "--token", "aa", "--amount", "1"]).1,
            Commands::TokenBurn { .. }
        ));
        assert!(matches!(
            parse_cmd(&["propose-token-authority", "--from", "k", "--token", "aa", "--mint-authority", "bb"]).1,
            Commands::ProposeTokenAuthority { .. }
        ));
        assert!(matches!(
            parse_cmd(&["vote-token-authority", "--from", "k", "--token", "aa", "--approve"]).1,
            Commands::VoteTokenAuthority { .. }
        ));
    }

    #[test]
    fn parse_call_chain_and_names() {
        assert!(matches!(
            parse_cmd(&["call-chain", "--from", "k", "--calls", "[]", "--simulate"]).1,
            Commands::CallChain { simulate: true, .. }
        ));
        assert!(matches!(
            parse_cmd(&["propose-name", "--from", "k", "--name", "n", "--target", "aa", "--owner", "bb"]).1,
            Commands::ProposeName { .. }
        ));
        assert!(matches!(
            parse_cmd(&["vote-name", "--from", "k", "--name", "n", "--approve"]).1,
            Commands::VoteName { .. }
        ));
        assert!(matches!(
            parse_cmd(&["renew-name", "--from", "k", "--name", "n"]).1,
            Commands::RenewName { .. }
        ));
        assert!(matches!(
            parse_cmd(&["transfer-name", "--from", "k", "--name", "n", "--new-owner", "aa"]).1,
            Commands::TransferName { .. }
        ));
    }

    #[test]
    fn parse_url_governance_and_visibility() {
        assert!(matches!(
            parse_cmd(&["propose-url", "--from", "k", "--url-pattern", "https://x/*", "--bond", "1"]).1,
            Commands::ProposeUrl { .. }
        ));
        assert!(matches!(
            parse_cmd(&["vote-url", "--from", "k", "--url-pattern", "https://x/*", "--approve"]).1,
            Commands::VoteUrl { .. }
        ));
        assert!(matches!(
            parse_cmd(&["report-malicious-url", "--from", "k", "--url-pattern", "https://x/*"]).1,
            Commands::ReportMaliciousUrl { .. }
        ));
        assert!(matches!(
            parse_cmd(&["upgrade-visibility", "--from", "k", "--cell-id", "aa"]).1,
            Commands::UpgradeVisibility { .. }
        ));
    }

    #[test]
    fn parse_sdk_and_manifest_commands() {
        assert!(matches!(
            parse_cmd(&["build", "--source", "src/lib.rs"]).1,
            Commands::Build { .. }
        ));
        assert!(matches!(
            parse_cmd(&["sdk-new", "--path", "p"]).1,
            Commands::SdkNew { .. }
        ));
        assert!(matches!(
            parse_cmd(&["sdk-build", "--path", "p"]).1,
            Commands::SdkBuild { .. }
        ));
        assert!(matches!(
            parse_cmd(&["sdk-deploy", "--from", "k", "--cell-id", "aa", "--path", "p"]).1,
            Commands::SdkDeploy { .. }
        ));
        assert!(matches!(
            parse_cmd(&["manifest-init", "--bytecode-file", "c.wasm"]).1,
            Commands::ManifestInit { .. }
        ));
        assert!(matches!(
            parse_cmd(&["manifest-verify", "--bytecode-file", "c.wasm", "--manifest-file", "m.json"]).1,
            Commands::ManifestVerify { .. }
        ));
        assert!(matches!(
            parse_cmd(&["manifest-hash", "--bytecode-file", "c.wasm", "--manifest-file", "m.json"]).1,
            Commands::ManifestHash { .. }
        ));
    }
}
