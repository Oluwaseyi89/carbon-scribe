# CarbonScribe Buffer Pool
**Carbon Credit Risk Mitigation Reserve**

![Stellar](https://img.shields.io/badge/Stellar-Soroban-blue)
![Rust](https://img.shields.io/badge/Rust-Smart_Contract-orange)
![Contract](https://img.shields.io/badge/Role-Insurance_Reserve-green)

The Buffer Pool contract is CarbonScribe's on-chain insurance reserve. It accumulates a configurable percentage of issued credits and gives governance a controlled mechanism to replace invalidated credits without breaking retirement integrity.

## Key Capabilities

- Automatic reserve replenishment in basis points
- Manual custody deposit support for admin and core asset contract
- Governance-only replacement withdrawals
- Per-token custody records with timestamp and project lineage
- Public TVL and custody query endpoints

## Table of Contents

1. [System Role](#system-role)
2. [Contract Architecture](#contract-architecture)
3. [Repository Structure](#repository-structure)
4. [Public Interface](#public-interface)
5. [Operational Flow](#operational-flow)
6. [Build and Test](#build-and-test)
7. [Testnet Deployment](#testnet-deployment)
8. [Security Notes](#security-notes)

## System Role

Within CarbonScribe's settlement layer, this contract acts as a protocol-level shock absorber:

1. Credits are minted in the primary carbon asset contract.
2. A configured reserve fraction is routed into this pool.
3. If credits are later invalidated, governance withdraws replacement credits from pool custody.
4. Corporate retirement trust remains protected by on-chain traceability.

## Contract Architecture

```text
+--------------------------+
| Carbon Asset Contract    |
| (mint and auto_deposit)  |
+------------+-------------+
             |
             v
+--------------------------+
| Buffer Pool Contract     |
| - custody records        |
| - replenishment rate     |
| - total value locked     |
+------------+-------------+
             |
             v
+--------------------------+
| Governance Withdrawal    |
| withdraw_to_replace(...) |
+--------------------------+
```

## Repository Structure

```text
buffer_pool/
|- src/
|  |- lib.rs              # contract logic and public entrypoints
|  |- storage.rs          # custody, tvl, and config keys
|  |- events.rs           # deposit and withdrawal events
|  |- errors.rs           # typed contract errors
|  \- test.rs             # unit tests
|- tests/
|  \- integration_test.rs # integration scenarios
\- Cargo.toml
```

## Public Interface

### Initialization

```rust
initialize(env, admin, governance, carbon_asset_contract, initial_percentage)
```

One-time setup with:

- `admin`: emergency and configuration authority
- `governance`: replacement withdrawal authority
- `carbon_asset_contract`: trusted auto-deposit caller
- `initial_percentage`: reserve rate in basis points, must be `0..=10000`

### Deposits

```rust
deposit(env, caller, token_id, project_id)
auto_deposit(env, carbon_contract_caller, token_id, project_id, total_minted)
```

- `deposit`: manual custody intake, restricted to admin or linked carbon contract
- `auto_deposit`: deterministic reserve intake, returns `true` when deposited

Selection formula:

`token_id % (10000 / percentage) == 0`

At 500 bps (5%), approximately every 20th token is reserved.

### Replacement Withdrawal

```rust
withdraw_to_replace(env, governance_caller, token_id, target_invalidated_token)
```

Governance removes a pool token to replace a specific invalidated token.

### Governance and Queries

```rust
set_governance_address(env, current_governance, new_governance)
set_replenishment_rate(env, governance, new_percentage)
get_total_value_locked(env)
get_custody_record(env, token_id)
is_token_in_pool(env, token_id)
```

## Operational Flow

```text
Mint -> auto_deposit decision -> custody write -> TVL increment
Invalidation event -> governance withdrawal -> TVL decrement -> replacement trace
```

## Build and Test

```bash
cd contracts/buffer_pool
cargo test
cargo build --target wasm32-unknown-unknown --release
```

## Testnet Deployment

```bash
cd contracts/buffer_pool
soroban contract deploy \
  --wasm ../../target/wasm32-unknown-unknown/release/buffer_pool.wasm \
  --source <IDENTITY_NAME> \
  --rpc-url https://soroban-testnet.stellar.org:443 \
  --network-passphrase "Test SDF Network ; September 2015"
```

## Security Notes

- Authorization checks enforce role boundaries for all privileged actions.
- Reserve rate is bounded to avoid invalid arithmetic and policy abuse.
- Duplicate custody entries are rejected.
- Withdrawals are limited to governance.
- Event emission supports auditable off-chain monitoring.
