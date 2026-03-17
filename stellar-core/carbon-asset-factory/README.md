# CarbonScribe Asset Factory
**Carbon Credit Tokenization and Retirement Core on Stellar Soroban**

![Stellar](https://img.shields.io/badge/Stellar-Soroban-blue)
![Rust](https://img.shields.io/badge/Rust-Smart_Contracts-orange)
![Climate](https://img.shields.io/badge/Use_Case-Carbon_Markets-green)

CarbonScribe Asset Factory is the smart contract backbone that mints carbon credits, anchors methodology provenance, records irreversible retirement, and provides protocol-level risk buffering for invalidation scenarios.

This repository is designed as the settlement and integrity layer for the broader CarbonScribe platform:

- Carbon projects issue tokenized credits.
- Corporates buy and transfer credits.
- Credits are retired on-chain with immutable proof.
- Buffer reserves protect market trust when credits are invalidated.

## Table of Contents

1. [System Vision](#system-vision)
2. [Repository Structure](#repository-structure)
3. [Contract Map](#contract-map)
4. [End-to-End Flow](#end-to-end-flow)
5. [Current Integration Status](#current-integration-status)
6. [Build and Test](#build-and-test)
7. [Deployment and Initialization Order](#deployment-and-initialization-order)
8. [Security and Governance Model](#security-and-governance-model)
9. [What to Extend Next](#what-to-extend-next)

## System Vision

The contract suite implements a practical on-chain carbon market core:

1. Methodologies are represented as trustable on-chain credentials.
2. Carbon credits are minted with metadata and lifecycle states.
3. Transfers can enforce compliance via pluggable policy checks.
4. Retirement is final, auditable, and queryable by token or entity.
5. A reserve pool supports replacement workflows after invalidation.

## Repository Structure

```text
carbon-asset-factory/
|- contracts/
|  |- buffer_pool/          # Insurance reserve and replacement custody
|  |- carbon_asset/         # Core carbon credit issuance and lifecycle
|  |- methodology_library/  # Methodology credential token registry
|  \- retirement_tracker/   # Immutable retirement ledger and burn orchestration
|- Cargo.toml               # Workspace and shared build profiles
\- README.md
```

## Contract Map

```text
+----------------------------+           +-----------------------------+
| Methodology Library        |           | Buffer Pool                 |
| - authority-managed        |           | - reserve custody           |
|   methodology tokens       |           | - governance replacement    |
+-------------+--------------+           +---------------+-------------+
							|                                          ^
							| methodology_id                           |
							v                                          |
+--------------------------------------------------------+-------------+
| Carbon Asset (C-01)                                                  |
| - mint, transfer, allowance                                           |
| - status and quality score                                            |
| - compliance hook                                                     |
+------------------------------+----------------------------------------+
															 |
															 | burn_token / retirement path
															 v
										+-----------------------------+
										| Retirement Tracker          |
										| - immutable retirement log  |
										| - retire and batch_retire   |
										+-----------------------------+
```

### 1) Carbon Asset

Purpose:

- Core token contract for carbon credits.
- Tracks ownership, metadata, status, quality score, and burn state.

Highlights:
              |                                          ^
              | methodology_id                           |
              v                                          |
- Count-based transfer and allowance interface.
- Optional external compliance validation hook.
- Oracle/admin quality score updates for dynamic credit modeling.

Directory:

                               |
                               | burn_token / retirement path
                               v
                    +-----------------------------+
                    | Retirement Tracker          |
                    | - immutable retirement log  |
                    | - retire and batch_retire   |
                    +-----------------------------+

Highlights:

- retire and batch_retire endpoints.
- Calls carbon asset burn_token during retirement flow.
- Stores timestamp, hash, retiring entity, and optional reason.

Directory:

- contracts/retirement_tracker

### 3) Buffer Pool

Purpose:

- Protocol reserve to support replacement after invalidation.

Highlights:

- Basis-point reserve policy.
- Manual and auto deposit entrypoints.
- Governance-only withdraw_to_replace.
- TVL and custody query endpoints.

Directory:

- contracts/buffer_pool

### 4) Methodology Library

Purpose:

- On-chain methodology provenance and authority trust registry.

Highlights:

- Admin-managed issuing authority list.
- Authorized methodology minting with metadata.
- Ownership and approval support.
- is_valid_methodology check based on live authority set.

Directory:

- contracts/methodology_library

## End-to-End Flow

### Issuance Flow

1. Admin or trusted issuer configures methodology references.
2. Admin mints carbon credits in Carbon Asset.
3. Metadata includes methodology id and project details.

### Trading and Compliance Flow

1. Credits transfer between wallets using transfer or transfer_from.
2. If configured, before_transfer calls external compliance contract.
3. Lifecycle status remains enforceable on-chain.

### Retirement Flow

1. Retiring entity calls Retirement Tracker retire.
2. Tracker invokes Carbon Asset burn_token.
3. Tracker writes immutable retirement record and emits event.
4. Reporting systems consume records by token id or entity.

### Invalidation and Replacement Flow

1. Reserve credits are deposited into Buffer Pool.
2. Governance executes withdraw_to_replace when needed.
3. Replacement event trail preserves accountability.

## Current Integration Status

What is already wired at contract level:

- Carbon Asset <-> Retirement Tracker burn path is implemented.
- Carbon Asset compliance hook is implemented and configurable.

What is currently modular but not directly enforced by cross-contract calls in current code:

- Carbon Asset does not currently auto-call Buffer Pool during mint.
- Carbon Asset does not currently enforce Methodology Library validation on mint.

Typical implementation pattern today:

- Enforce these links in orchestration services (backend/indexer), or
- Add explicit cross-contract calls in a future contract version.

## Build and Test

From repository root:

```bash
cargo test
cargo build --target wasm32-unknown-unknown --release
```

Build one contract only:

```bash
cargo build -p carbon_asset --target wasm32-unknown-unknown --release
cargo build -p retirement_tracker --target wasm32-unknown-unknown --release
cargo build -p buffer_pool --target wasm32-unknown-unknown --release
cargo build -p methodology_library --target wasm32-unknown-unknown --release
```

## Deployment and Initialization Order

Recommended order on testnet:

1. Deploy all four WASM contracts.
2. Initialize Methodology Library.
3. Initialize Carbon Asset with Retirement Tracker address.
4. Initialize Retirement Tracker with Carbon Asset address.
5. Initialize Buffer Pool with Carbon Asset and governance addresses.
6. Configure optional governance and compliance settings:
   - set_regulatory_check
   - set_host_jurisdiction
   - set_oracle

Example deploy command:

```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/carbon_asset.wasm \
  --source <IDENTITY_NAME> \
  --rpc-url https://soroban-testnet.stellar.org:443 \
  --network-passphrase "Test SDF Network ; September 2015"
```

## Security and Governance Model

- Initialization is one-time for core contracts.
- Role-gated functions require auth checks.
- Retirement records are immutable once written.
- Reserve withdrawals are governance-controlled.
- External compliance logic is opt-in and upgradeable by admin controls.
- Events across contracts support audit and transparency pipelines.

## What to Extend Next

1. Add direct mint-time Buffer Pool hook in Carbon Asset.
2. Add on-chain methodology validation during mint.
3. Add stronger admin patterns (multisig, timelock, role split).
4. Add formal deployment scripts and environment manifests for testnet/mainnet.

