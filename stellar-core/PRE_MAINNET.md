# Stellar Core Pre-Mainnet Issue Backlog

This backlog captures concrete issues observed in the current `stellar-core` contract code and the required steps to reach mainnet readiness.

Scope includes all 10 active Soroban contracts:
- carbon_asset
- retirement_tracker
- buffer_pool
- methodology_library
- regulatory_checks
- tax_attribute
- audit_trail
- registry_contract
- merkle_bridge
- time_lock

Current validation snapshot from this branch:
- `carbon-asset-factory`: tests pass
- `compliance-engine`: tests pass, but two contracts have zero unit tests
- `verifiable-registry`: tests pass, but one contract has zero unit tests

## Carbon Asset (20 issues)

1. Replace generic `InvalidStatusTransition` usage for amount/ledger validation with dedicated SEP-41 input errors.
2. Add explicit max supply / mint cap controls to prevent unbounded token issuance.
3. Add input bounds validation for metadata fields (length and format constraints).
4. Enforce methodology validation on mint via cross-contract call to `methodology_library`.
5. Add optional requirement that `methodology_id` must exist before mint completion.
6. Add mint-time host jurisdiction normalization and canonical code validation.
7. Add safe increment check for `NextTokenId` overflow handling.

9. Add invariant test ensuring burned tokens can never reappear in owner token lists.
10. Add dedicated tests for all rejected status transitions (full transition matrix).
11. Add dedicated tests for compliance hook failure paths (contract missing, malformed response).
12. Handle external compliance contract invocation failures with deterministic contract errors.
13. Add transfer throttling / circuit-breaker switch for emergency governance response.
14. Add two-step admin transfer (propose/accept) instead of immediate reassignment.
15. Add multisig-compatible admin model (role split for mint/config/oracle actions).
16. Add explicit deprecation path for oracle rotation to avoid single-block trust flips.
17. Add explicit check that retirement tracker address is contract account at configuration time.
18. Add integration path for automatic buffer pool deposit during mint (currently only documented).
19. Add storage TTL extension strategy for long-lived owner/token mappings.
20. Add formal invariant fuzz tests for SEP-41 amount transfer behavior over token-indexed ownership.

## Retirement Tracker (20 issues)

21. Replace `panic!("Contract already initialized")` with typed contract error.
22. Add validation for `token_id > 0` and reject invalid IDs with explicit errors.

24. Validate burn call return/error surface from `carbon_asset` and map to `BurnFailed`.
25. Add explicit cross-contract interface checks during initialization (method existence sanity).
26. Add duplicate retirement prevention test across `retire` and `batch_retire` interleavings.
27. Add failure reporting in `batch_retire` (currently silently drops failed entries).
28. Add batch upper bound to prevent resource exhaustion on very large token arrays.
29. Add event for failed retirement attempts to improve auditability.
30. Add index compaction/cleanup strategy for very large `EntityIndex` vectors.
31. Add pagination query for retirements by entity to support large histories.
32. Add method to fetch retirement record count for deterministic pagination.
33. Add immutable admin rotation delay/timelock on `update_carbon_asset_contract`.
34. Add freeze switch that blocks contract address updates after governance finalization.
35. Add storage TTL extension policy for retirement ledger permanence.
36. Add full unit tests (currently zero tests for this contract).
37. Add adversarial tests for malicious carbon asset contract responses.
38. Add reentrancy-safety review for external invocation sequencing.
39. Add canonical reason string limits and sanitization for reporting fields.
40. Add deployment-time handshake test proving round-trip retire -> burn -> record correctness.

## Buffer Pool (20 issues)

41. Require auth on `initialize` caller path and enforce admin/governance signer checks.
42. Add guard against `percentage = 0` in `auto_deposit` to prevent modulo-by-zero panic.
43. Enforce non-zero governance and carbon contract addresses at initialization.
44. Add validation that deposited token actually exists and is custodied by pool contract.
45. Add cross-contract transfer-in call to ensure custody is real, not metadata-only.

47. Add TVL underflow/overflow protections using checked arithmetic.
48. Add duplicate-token protection in `auto_deposit` path (same token deposited twice).
49. Add replacement eligibility checks for `target_invalidated_token` before withdrawal.
50. Add explicit mapping between replacement token and invalidated token for traceability.
51. Add event for governance parameter changes (rate and governance address updates).
52. Add query for all custody records with pagination.
53. Add query for project-level reserve balances and exposure metrics.
54. Add reserve policy versioning to track parameter evolution over time.
55. Add emergency pause for deposits/withdrawals under incident response.
56. Add role split between reserve manager and governance policy owner.
57. Add TTL extension policy for custody records and policy state.
58. Add invariant tests ensuring TVL equals custody record cardinality.
59. Add integration tests with `carbon_asset` mint/deposit workflows.
60. Add stress tests for high-throughput mint/deposit scenarios.

## Methodology Library (20 issues)


62. Move critical config keys to instance storage where appropriate for lower rent pressure.
63. Add metadata schema validation for `name`, `version`, and `registry_link` fields.
64. Add URI format validation for `registry_link` and CID format validation for `ipfs_cid`.
65. Add uniqueness constraints for methodology identity (name+version+registry combination).
66. Add revocation/suspension status field for methodology tokens.
67. Add explicit historical validity checks rather than current-authority-only evaluation.
68. Add authority validity windows (start/end timestamps).
69. Add two-step authority add/remove governance flow with delay.
70. Add event for admin initialization and authority list bootstrap.
71. Add event for metadata updates and revocations.
72. Add bounded authority list size and pagination methods.
73. Replace `unwrap()` on authority vector access with typed error handling.
74. Add full approval/transfer edge-case tests for token ownership semantics.
75. Add tests for unauthorized initialize and duplicate initialize paths.
76. Add tests for revoked authority behavior on historical token validity.
77. Add compatibility layer for external registry proof verification.
78. Add storage TTL policy for methodology and authority data.
79. Add cross-contract validation endpoint tailored for carbon mint pre-checks.
80. Add mainnet migration plan for pre-existing off-chain methodology catalog import.

## Regulatory Checks (20 issues)

81. Add one-time initialization guard (currently can overwrite admin/governance).
82. Replace all `unwrap()` governance/admin retrievals with typed initialization errors.
83. Add validation that carbon asset contract address is non-zero and contract account.
84. Add explicit rule schema validation (non-empty IDs, field length caps, enum consistency).

86. Add deterministic rule priority ordering to avoid first-match ambiguity.
87. Add rule versioning and immutable history for audit/legal traceability.
88. Add support for time-bounded rule activation windows.
89. Add event emissions for add/update/deactivate rule lifecycle changes.
90. Add event emissions for jurisdiction updates on addresses.
91. Add pagination for active rule IDs and filtered rule retrieval.
92. Add optimization for large rule sets (indexed match keys instead of linear scan).
93. Add explicit fail-open/fail-closed policy switch for integration outages.
94. Add approval key generation standard and nonce/collision controls.
95. Add cleanup and TTL extension strategy for pending approvals.
96. Add tests for `record_authorization` expiry boundary conditions.
97. Add tests for no-matching-rule policy behavior under production config.
98. Add full unit tests (currently zero tests for this contract).
99. Add integration tests with `carbon_asset.before_transfer` and retirement flows.
100. Add governance timelock and multisig requirement for rule changes on mainnet.

## Tax Attribute (20 issues)

101. Replace all `panic!` auth and validation paths with structured contract errors.
102. Add one-time initialization guard with typed error return.
103. Require admin auth in initialization flow for explicit ownership acceptance.
104. Add validation that `valid_from <= valid_until` for attribute definitions.

106. Add explicit uniqueness strategy for `tag_id` namespace (global vs token-scoped).
107. Add immutable revocation status flag instead of removing links only.
108. Add revocation event emission with actor, reason, and timestamp.
109. Add attachment event emission for each new tax attribute link.
110. Add query to retrieve attribute by `tag_id` directly.
111. Add pagination for token attribute lists.
112. Add issuer list bounds and pagination for `AllIssuers`.
113. Add issuer add/remove events and governance audit trail.
114. Add deterministic issuer authorization proof endpoint for off-chain engines.
115. Add TTL extension policy for attributes and token links.
116. Add tests for unauthorized issuer attach/revoke cases.
117. Add tests for duplicate tag IDs and duplicate attachment attempts.
118. Add tests for eligibility behavior around validity window boundaries.
119. Add replay and ordering tests for concurrent revoke/attach operations.
120. Add full unit tests (currently zero tests for this contract).

## Audit Trail (20 issues)

121. Replace all `panic!` branches with typed errors for deterministic client handling.
122. Remove or disable `record_event` panic stub and converge on single production entrypoint.
123. Replace emitter self-declaration model with stronger caller provenance validation.
124. Add one-time initialization guard returning error instead of panic.

126. Add canonical event type registry or namespace validation.
127. Add stronger event ID construction (include nonce/index to avoid collisions).
128. Add optional hash chaining between events for tamper-evident audit streams.
129. Add retention strategy for `Events` and index TTL renewal.
130. Add pruning/archive policy for large entity/type indexes.
131. Add pagination for `get_events_by_contract` and `get_events_by_type_and_time`.
132. Add filtered query support (time range, event type prefix, entity prefix).
133. Add event for emitter authorization/revocation actions.
134. Add governance controls for emergency emitter freeze.
135. Add replay protection if authorized emitters resubmit identical payloads.
136. Add compatibility schema for external SIEM/audit export pipelines.
137. Add benchmark tests for high-volume event insertion.
138. Add fuzz tests for index consistency across all query methods.
139. Add migration strategy for schema changes in `AuditEvent`.
140. Add runbook for index rebuild from events in disaster recovery.

## Registry Contract (20 issues)

141. Add max project count / quota strategy to protect storage growth.
142. Add project ID format validation and normalization rules.
143. Add owner transfer guard against null/invalid destination addresses.
144. Add duplicate CID protection per project version history.

146. Add document type allowlist or policy hooks.
147. Add event for project registration and ownership transfer.
148. Add event for batch anchor summary in addition to per-document events.
149. Add pagination endpoint for document history retrieval.
150. Add pagination endpoint for projects by anchorer retrieval.
151. Add deduplicated anchorer index compaction strategy.
152. Add TTL extension policy for project owner and history state.
153. Add batch size upper bound to prevent resource exhaustion.
154. Add stronger CID validation including codec/multihash consistency checks.
155. Add tests for unauthorized registration/transfer paths.
156. Add tests for large history retrieval and pagination stability.
157. Add tests for duplicate project IDs across case variants.
158. Add optional linkage checks against external compliance project registry.
159. Add governance pattern for admin rotation (two-step with delay).
160. Add backup/export script and checksum process for anchored history continuity.

## Merkle Bridge (20 issues)

161. Implement actual `carbon_asset` mint integration (currently tracked as deferred in code comments).
162. Require carbon asset contract to be configured before `mint_wrapped` execution.

164. Define and enforce canonical Merkle tree serialization spec shared with relayer.
165. Include leaf position semantics in proof verification (currently ordering ignores `_leaf_index`).
166. Add replay protection keyed by `(epoch_id, registry_credit_id)` with explicit invariants.
167. Add admin/updater rotation events and historical audit map.
168. Add root finalization delay or challenge period before minting from new epoch.
169. Add emergency epoch freeze for compromised relayer scenarios.
170. Add cross-check that retired credits cannot be reactivated by future roots.
171. Add retention/TTL strategy for `MerkleRoot`, minted, and retired flags.
172. Add pagination/query methods for bridged credits by epoch.
173. Add events for failed proof attempts (optional rate-limited telemetry).
174. Add benchmark tests for worst-case proof depth and budget usage.
175. Add fuzz tests for hash ordering and proof validation edge cases.
176. Add tests for empty proof + non-zero index and other malformed proof states.
177. Add integration tests with external relayer artifact generation.
178. Add deployment checklist for updater key custody and rotation ceremony.
179. Add governance policy for root source attestation and signer quorum.
180. Add incident response playbook for erroneous root publication rollback strategy.

## Time Lock (20 issues)


182. Add unit/integration tests (currently zero tests for this contract).
183. Verify token transfer semantics: token ID should not be treated as fungible amount via SEP-41 client.
184. Integrate with NFT-style transfer interface if required by `carbon_asset` ownership model.
185. Add explicit ownership pre-check before lock transfer call.
186. Add bounded batch size for `batch_release` to avoid budget exhaustion.
187. Add pagination for `get_all_locked` and `get_tokens_locked_until`.
188. Add reverse index by owner for efficient owner-based lock queries.
189. Add TTL extension policy for lock record map.
190. Add event for admin/config updates (`set_admin`, `set_validate_vintage`).
191. Add two-step admin transfer with acceptance flow.
192. Add governance timelock before disabling vintage validation.
193. Replace year-seconds approximation with precise date arithmetic for vintage windows.
194. Add fallback behavior when vintage oracle call fails (explicit policy).
195. Add validation for `vintage` contract interface compatibility during configuration.
196. Add pause switch for lock/release operations during incident response.
197. Add force-release reason code and enhanced audit metadata.
198. Add invariant tests for lock lifecycle (lock -> release/force_release -> removed state).
199. Add tests for duplicate lock attempts and concurrent release races.
200. Add mainnet readiness drill: simulated keeper-driven release operations over large lock sets.

## Execution Notes

- This list is intentionally issue-oriented, not PR-oriented.
- Each item is scoped to be trackable as a GitHub issue with acceptance criteria and tests.
- Recommended next step: tag issues by `contract`, `security`, `compliance`, `testing`, `ops`, and `mainnet-blocker`.
