
# 181. Replace Initialization Panic with Typed `AlreadyInitialized` Error

Update the `time_lock` contract to replace any panic or generic error thrown during repeated initialization with a typed, deterministic `AlreadyInitialized` contract error, improving client handling and contract reliability.

## Technical Context

- **Contract**: time_lock (see PRE_MAINNET.md, Issue 181)
- **Motivation**: Panics or generic errors on repeated initialization are non-deterministic and hard for clients to handle. A typed error allows for clear, predictable contract behavior and better integration with off-chain systems.
- **Current State**: The contract panics or throws a generic error if `initialize` is called more than once.

## Requirements

### Contract Changes

- Refactor the `initialize` function to check if the contract is already initialized.
- If so, return a typed `AlreadyInitialized` error instead of panicking or using a generic error.
- Ensure the error is documented and surfaced in contract ABI.

### Acceptance Criteria

- Repeated calls to `initialize` return a typed `AlreadyInitialized` error.
- No panics or generic errors remain for this case.
- Unit tests cover:
	- Successful first initialization
	- Typed error on repeated initialization

### Definition of Done

- PR with contract code changes and tests
- Documentation updated to describe the error
- Team review completed

### Working Directory:

`stellar-core/verifiable-registry/contracts/time_lock`

---
