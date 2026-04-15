---
eip: (TBD — assigned on PR)
title: Tamper-Evident AI Agent Execution Audit Trail Standard
description: A standard for creating cryptographically verifiable, tamper-evident audit trails of AI agent execution history. It enables regulatory compliance and post-hoc verification by committing periodic Merkle roots on-chain and supporting on-demand ZK audit proofs, while extending ERC-8126 and complementing ERC-8004.
author: lejuho(@lejuoho
discussions-to: (Ethereum Magicians URL — create thread first)
status: Draft
type: Standards Track
category: ERC
created: 2026-04-14
requires: 8126, 712, 155
---

## Abstract

This ERC defines a standard interface for creating tamper-evident,
cryptographically verifiable audit trails of AI agent execution history.

While ERC-8004 addresses agent identity and reputation, and ERC-8126
addresses point-in-time security verification, no standard currently
provides a canonical record of what code an agent executed, what data
it consumed, and what outputs it produced over time — records that
regulators, auditors, and counterparties increasingly require.

This standard introduces:

1. An off-chain execution log structure with periodic on-chain
   commitment via Merkle root, minimizing gas costs regardless
   of execution frequency
2. A ZK-compatible agent code structure specification
   (ZK Preconditions) enabling efficient audit proof generation
3. TLS Notary binding for verifiable external data consumption
   records that cannot be retroactively deleted
4. A recursive proof aggregation pattern compressing full audit
   periods into a single verifiable proof
5. A crowdsourced reviewer network with crypto-economic slashing
   for audit certification
6. An extension interface (`IVerificationHook`) allowing future
   audit scope expansion without modifying this standard
7. A pipeline context interface (`IPipelineContext`) for
   multi-agent audit trail aggregation

---

## Motivation

### The Gap Between Execution and Accountability

When an AI agent executes a financial transaction, generates a legal
document, or makes a medical recommendation, there is no standard way
to subsequently prove:

- Which version of code produced the output
- Which external data sources were consumed
- Whether the consumed data was authentic and unmodified
- What the complete execution history was over a given period

Existing standards address adjacent problems but leave this gap open:

ERC-8004 addresses agent identity and reputation:
"This agent exists and has a trust score."

ERC-8126 addresses point-in-time security verification:
"This agent passed these checks at this moment."

Neither addresses longitudinal accountability:
"This agent, using this code, consuming this verified data,
produced these outputs over this period."

This gap is inconsequential for low-stakes automation. It becomes
critical when:

- Regulators require audit trails (MiFID II, SEC, GDPR, EU AI Act)
- Counterparties dispute agent-generated outputs
- Insurance underwriters assess AI agent operational risk
- Internal compliance teams review agent behavior over time
- M&A due diligence requires review of automated decision history

### Why Existing Approaches Are Insufficient

**Sigstore / cosign**
Signs container images at build time. Cannot prove what code ran
at a specific time during operation, nor what data was consumed
during execution. Does not address longitudinal execution history.

**ERC-8126 WAV (Web Application Verification)**
Verifies that an HTTPS endpoint is reachable at a point in time.
Does not verify what code executes behind that endpoint, nor
produce an ongoing execution record.

**ERC-8126 PDV (Private Data Verification)**
Generates ZK proofs of verification results but is point-in-time
and leaves proof generation mechanisms unspecified.

**Centralized audit logs**
Application-level logs are mutable by operators, lack external
attestation for data sources, and cannot be verified by third
parties without trusting the log operator.

### Why a New Standard Is Needed Now

**Condition 1: Regulated industries adopting AI agents**
Financial institutions, legal firms, and healthcare providers are
deploying AI agents for consequential decisions. Regulators in major
jurisdictions are beginning to require audit trails for automated
decision-making. The infrastructure to produce these trails does not
yet exist as a standard.

**Condition 2: ZK proof generation is now practical**
TLSNotary provides a production-ready protocol for proving TLS
session contents without exposing session keys. Nova/HyperNova
folding schemes make it practical to compress an entire audit period
into a single verifiable proof on demand.

**Condition 3: The standard layer is unoccupied**
ERC-8004's Validation Registry is deliberately unopinionated about
implementation. ERC-8126 provides registration and crypto-economic
infrastructure but does not define execution audit trails. This ERC
occupies the gap both standards deliberately leave open, providing
an execution audit layer on top of the existing identity and
verification infrastructure.

### Design Goals

**Align with regulatory requirements**
Audit trail requirements exist today in financial services
(MiFID II, SEC Rule 17a-4), healthcare (HIPAA), and are emerging
for AI systems specifically (EU AI Act Article 12). This standard
is designed so that compliance can be demonstrated through a single
audit report rather than custom implementations per jurisdiction.

**Minimize gas costs through periodic commitment**
Per-call on-chain submission would make audit trails prohibitively
expensive for high-frequency agents. Periodic Merkle root commitment
reduces on-chain costs to a fixed overhead regardless of execution
frequency, while preserving the ability to prove any individual
execution within the committed period.

**Remain execution environment agnostic**
Agents run on AWS Lambda, GCP Cloud Run, bare metal, and everything
in between. This standard makes no assumptions about the execution
environment.

**Enable composability**
Multi-agent pipelines require that individual agent audit trails
can be composed into pipeline-level audit records. This standard
defines the proof interface such that individual execution logs
can be aggregated using recursive ZK schemes without modification
to the base standard.

---

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
RFC 2119 and RFC 8174.

---

### 3.1 Interface Definitions

#### 3.1.1 Core Audit Registry Interface

Extends ERC-8126's `IERCXXXX` interface with execution audit fields.

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.0;

import "./IERC8126.sol";

interface IAgentAuditRegistry is IERC8126 {

    // ─── Structs ───────────────────────────────

    /// @notice Code integrity record for an agent
    struct CodeRecord {
        // Hash of the agent codebase at registration
        // MUST be SHA-256 of the canonical source tree
        bytes32 codebaseHash;

        // Dependency set hash
        // MUST be SHA-256 of canonical dependency manifest
        bytes32 dependencyHash;

        // Sigstore bundle URI
        // MUST be a valid HTTPS URI
        string sigstoreBundle;

        // Trust tier at registration time
        // 1 = Sigstore only (Phase 1)
        // 2 = Crowd-sourced verifier consensus (Phase 2)
        // 3 = ZK proof verified (Phase 3)
        // 4+ = Reserved for future extension
        uint8 trustTier;

        // Block number when this record was registered
        uint256 registeredAt;

        // Whether this record has been superseded
        bool superseded;
    }

    /// @notice Single execution log entry (stored off-chain)
    /// @dev This struct defines the canonical format for
    ///      off-chain log entries. Only the Merkle root
    ///      of a batch of entries is committed on-chain.
    struct ExecutionLogEntry {
        // Agent that executed
        bytes32 agentId;

        // Code version at execution time
        bytes32 codebaseHash;

        // Hash of inputs consumed
        bytes32 inputHash;

        // Hash of outputs produced
        bytes32 outputHash;

        // TLS Notary attestations for external data consumed
        // MAY be empty if no external calls were made
        bytes tlsAttestation;

        // IPFS CID of full execution log for this entry
        string logCID;

        // Timestamp of execution
        uint256 executedAt;

        // Trust tier used for this execution
        uint8 trustTier;
    }

    /// @notice On-chain commitment for a batch of execution logs
    struct ExecutionCommitment {
        // Agent whose executions are committed
        bytes32 agentId;

        // Period covered by this commitment
        uint256 periodStart;
        uint256 periodEnd;

        // Merkle root of all ExecutionLogEntries in period
        // Enables proving any individual entry without
        // storing all entries on-chain
        bytes32 executionLogRoot;

        // Number of entries committed
        uint256 entryCount;

        // Block number of commitment
        uint256 committedAt;
    }

    /// @notice Audit period record — produced on audit request
    struct AuditPeriod {
        // Agent being audited
        bytes32 agentId;

        // Commitment covering this period
        bytes32 commitmentId;

        // ZK proof covering entire period
        // Generated on demand, not stored until certified
        bytes auditProof;

        // IPFS CID of human-readable audit report
        string auditReportCID;

        // Whether audit has been certified by reviewer
        bool certified;

        // Human Review certification reference
        bytes32 reviewId;

        // Block number of audit request
        uint256 requestedAt;
    }

    /// @notice Pipeline audit record
    struct PipelineAuditRecord {
        // Unique pipeline execution ID
        bytes32 pipelineId;

        // Ordered list of agentIds in this pipeline
        bytes32[] agentIds;

        // Ordered list of commitmentIds per agent
        bytes32[] commitmentIds;

        // Aggregated recursive ZK proof covering all agents
        bytes aggregatedProof;

        // Whether pipeline audit is finalized
        bool finalized;
    }

    // ─── Events ───────────────────────────────

    /// @notice Emitted when a code record is registered
    event CodeRecordRegistered(
        bytes32 indexed agentId,
        bytes32 indexed codebaseHash,
        uint8 trustTier,
        string sigstoreBundle
    );

    /// @notice Emitted when a code record is superseded
    event CodeRecordSuperseded(
        bytes32 indexed agentId,
        bytes32 indexed oldCodeHash,
        bytes32 indexed newCodeHash
    );

    /// @notice Emitted when an execution log batch is committed
    event ExecutionLogCommitted(
        bytes32 indexed agentId,
        bytes32 indexed commitmentId,
        bytes32 executionLogRoot,
        uint256 entryCount,
        uint256 periodStart,
        uint256 periodEnd
    );

    /// @notice Emitted when an audit is requested
    event AuditRequested(
        bytes32 indexed auditId,
        bytes32 indexed agentId,
        bytes32 commitmentId
    );

    /// @notice Emitted when an audit proof is submitted
    event AuditProofSubmitted(
        bytes32 indexed auditId,
        bytes auditProof,
        string auditReportCID
    );

    /// @notice Emitted when an audit is certified
    event AuditCertified(
        bytes32 indexed auditId,
        bytes32 indexed reviewId
    );

    /// @notice Emitted when an audit entry is challenged
    event AuditEntryChallenged(
        bytes32 indexed commitmentId,
        bytes32 indexed challenger,
        bytes evidence
    );

    /// @notice Emitted when a pipeline audit is finalized
    event PipelineAuditFinalized(
        bytes32 indexed pipelineId,
        bytes32[] agentIds,
        bytes aggregatedProof
    );

    // ─── Errors ───────────────────────────────

    error InvalidAddress();
    error InvalidCodeHash();
    error AgentNotFound();
    error UnauthorizedAccess();
    error CodeHashAlreadyRegistered();
    error CodeHashSuperseded();
    error InvalidSigstoreBundle();
    error MissingTier3Certification();
    error InvalidMerkleRoot();
    error CommitmentPeriodInvalid();
    error AuditNotFound();
    error AuditAlreadyCertified();
    error InvalidAuditProof();
    error InvalidNotary();
    error AttestationExpired();
    error CommitmentAlreadyUsed();
    error UndeclaredInterface();
    error MissingAttestation();
    error InvalidNotarySignature();
    error InsufficientStake();
    error InsufficientFee();
    error ReviewerIneligible();
    error UnauthorizedReviewer();
    error ChallengePeriodExpired();
    error InsufficientReviewers();
    error InputOutputMismatch();
    error StepOutOfOrder();
    error IncompletePipeline();
    error AgentIdMismatch();
    error TLSCommitmentCountMismatch();
    error PipelineAlreadyFinalized();
    error PipelineAgentMismatch();
    error Unauthorized();
    error InvalidHookAddress();
    error InsufficientNotaryThreshold();
    error LogRootMismatch();

    // ─── Code Registration ─────────────────────

    /// @notice Register a codebaseHash for an existing ERC-8126 agent
    /// @dev MUST revert if agentId does not exist in ERC-8126 registry
    /// @dev MUST revert if caller is not walletAddress or registrantAddress
    function registerCodeRecord(
        bytes32 agentId,
        bytes32 codebaseHash,
        bytes32 dependencyHash,
        string calldata sigstoreBundle
    ) external returns (bytes32 recordId);

    /// @notice Update codebaseHash (new version)
    /// @dev Previous record MUST be marked superseded
    function updateCodeRecord(
        bytes32 agentId,
        bytes32 newCodebaseHash,
        bytes32 newDependencyHash,
        string calldata newSigstoreBundle
    ) external returns (bytes32 recordId);

    /// @notice Retrieve the active code record for an agent
    function getCodeRecord(
        bytes32 agentId
    ) external view returns (CodeRecord memory);

    /// @notice Retrieve code record by recordId
    function getCodeRecordById(
        bytes32 recordId
    ) external view returns (CodeRecord memory);

    // ─── Execution Log Commitment ───────────────

    /// @notice Commit a batch of execution logs as a Merkle root
    /// @dev Called periodically (not per-execution) to minimize gas
    /// @dev MUST revert if executionLogRoot is zero
    /// @dev MUST revert if periodEnd <= periodStart
    /// @param agentId Agent whose executions are committed
    /// @param executionLogRoot Merkle root of ExecutionLogEntry batch
    /// @param entryCount Number of entries in the batch
    /// @param periodStart Unix timestamp of first entry
    /// @param periodEnd Unix timestamp of last entry
    /// @param logBundleCID IPFS CID of full off-chain log bundle
    /// @return commitmentId Unique identifier for this commitment
    function commitExecutionLog(
        bytes32 agentId,
        bytes32 executionLogRoot,
        uint256 entryCount,
        uint256 periodStart,
        uint256 periodEnd,
        string calldata logBundleCID
    ) external returns (bytes32 commitmentId);

    /// @notice Retrieve an execution commitment
    function getCommitment(
        bytes32 commitmentId
    ) external view returns (ExecutionCommitment memory);

    /// @notice Verify that a specific ExecutionLogEntry is
    ///         included in a commitment via Merkle proof
    /// @param commitmentId Commitment to verify against
    /// @param entry The execution log entry to verify
    /// @param merkleProof Merkle proof for this entry
    /// @return valid Whether the entry is in the commitment
    function verifyLogEntry(
        bytes32 commitmentId,
        ExecutionLogEntry calldata entry,
        bytes32[] calldata merkleProof
    ) external view returns (bool valid);

    // ─── Audit Request and Proof ────────────────

    /// @notice Request an audit for a commitment period
    /// @dev Triggers off-chain ZK proof generation
    /// @dev Caller pays audit fee
    /// @param commitmentId Commitment to audit
    /// @return auditId Unique identifier for this audit request
    function requestAudit(
        bytes32 commitmentId
    ) external payable returns (bytes32 auditId);

    /// @notice Submit ZK proof for an audit period
    /// @dev Called after off-chain proof generation completes
    /// @dev MUST revert if auditProof fails on-chain verification
    /// @param auditId Audit request identifier
    /// @param auditProof ZK proof covering all entries in period
    /// @param auditReportCID IPFS CID of human-readable audit report
    function submitAuditProof(
        bytes32 auditId,
        bytes calldata auditProof,
        string calldata auditReportCID
    ) external;

    /// @notice Retrieve an audit period record
    function getAudit(
        bytes32 auditId
    ) external view returns (AuditPeriod memory);

    /// @notice Check if an audit is certified
    function isAuditCertified(
        bytes32 auditId
    ) external view returns (bool);

    // ─── Pipeline Audit ─────────────────────────

    /// @notice Initialize a pipeline audit record
    function initPipelineAudit(
        bytes32[] calldata agentIds
    ) external returns (bytes32 pipelineId);

    /// @notice Attach a commitment to a pipeline audit step
    function attachPipelineCommitment(
        bytes32 pipelineId,
        uint256 stepIndex,
        bytes32 commitmentId
    ) external;

    /// @notice Finalize pipeline audit with aggregated proof
    function finalizePipelineAudit(
        bytes32 pipelineId,
        bytes calldata aggregatedProof
    ) external;

    /// @notice Retrieve a pipeline audit record
    function getPipelineAudit(
        bytes32 pipelineId
    ) external view returns (PipelineAuditRecord memory);

    // ─── Extension Hooks ───────────────────────

    /// @notice Register a custom verification hook for a trust tier
    /// @dev MUST only be callable by governance
    function registerVerificationHook(
        uint8 trustTier,
        address hookAddress
    ) external;

    /// @notice Register a custom pipeline context hook
    function registerPipelineHook(
        address hookAddress
    ) external;
}
```

#### 3.1.2 Verification Hook Interface

```solidity
/// @notice Interface for pluggable verification methods
interface IVerificationHook {

    /// @notice Validate a proof for a given agent and code hash
    /// @return valid Whether proof is valid
    /// @return trustScore 0-100 confidence score
    function verify(
        bytes32 agentId,
        bytes32 claimedCodeHash,
        bytes calldata proof,
        bytes calldata context
    ) external returns (
        bool valid,
        uint8 trustScore
    );

    function trustTier() external view returns (uint8);
    function description() external view returns (string memory);
}
```

#### 3.1.3 Pipeline Context Hook Interface

```solidity
/// @notice Interface for pipeline-level hooks
interface IPipelineContext {

    function onStepComplete(
        bytes32 pipelineId,
        uint256 stepIndex,
        bytes32 agentId,
        bytes32 outputHash,
        bytes calldata proof
    ) external;

    function onPipelineFinalized(
        bytes32 pipelineId,
        bytes calldata aggregatedProof
    ) external;
}
```

#### 3.1.4 Slashing Condition Interface

```solidity
/// @notice Interface for pluggable slashing conditions
interface ISlashingCondition {

    function evaluate(
        bytes32 agentId,
        bytes32 commitmentId,
        bytes calldata evidence
    ) external returns (
        bool shouldSlash,
        uint256 slashAmount,
        string memory reason
    );
}
```

---

### 3.2 ZK Preconditions

ZK Preconditions define the structural requirements that agent code
MUST satisfy to be eligible for Tier 3 (ZK proof) audit certification.

The motivation: arbitrary code is not efficiently provable in ZK
circuits. By constraining the structure of agent code at registration
time, proof generation for audit periods becomes tractable without
requiring the prover to encode unbounded non-determinism.

Agents that do not satisfy ZK Preconditions MAY still register and
operate at Tier 1 or Tier 2. ZK Preconditions are a requirement only
for Tier 3 audit proof generation.

The Human Review Layer (Section 3.4) is responsible for certifying
that a submitted codebase satisfies ZK Preconditions before a Tier 3
CodeRecord can be registered.

#### 3.2.1 Precondition Definitions

**PC-1: Declared External Interface**

All external calls MUST be declared in a machine-readable manifest:

    /.zkagent/interfaces.json

The manifest MUST enumerate each external endpoint, input/output
schemas, and whether the call is deterministic.

```json
{
  "version": "1.0",
  "interfaces": [
    {
      "id": "price-oracle",
      "endpoint": "https://api.example.com/price/*",
      "deterministic": false,
      "input_schema": {
        "type": "object",
        "properties": { "symbol": { "type": "string" } }
      },
      "output_schema": {
        "type": "object",
        "properties": {
          "price": { "type": "number" },
          "timestamp": { "type": "integer" }
        }
      }
    }
  ]
}
```

**PC-2: Isolated Non-Determinism**

Non-deterministic components MUST be isolated behind a single
declared entry point per component type.

```
Agent execution model:

┌─────────────────────────────────────────┐
│  Provable Region (ZK circuit covers)    │
│  input parsing / routing / formatting   │
│  ┌───────────────────────────────────┐  │
│  │  Black-box Region (excluded)      │  │
│  │  LLM inference entry point        │  │
│  │  RNG entry point                  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**PC-3: No Global Mutable State**

The agent MUST NOT read from or write to mutable state that persists
across invocations and is not passed explicitly as input.

**PC-4: Explicit Input/Output Contract**

The agent MUST expose a typed invocation interface declared at:

    /.zkagent/contract.json

inputHash and outputHash in ExecutionLogEntry MUST be computed as:

    SHA-256(canonical_serialize(input))
    SHA-256(canonical_serialize(output))

```json
{
  "version": "1.0",
  "input": {
    "type": "object",
    "properties": {
      "query": { "type": "string" },
      "context": { "type": "array" }
    },
    "required": ["query"]
  },
  "output": {
    "type": "object",
    "properties": {
      "result": { "type": "string" },
      "confidence": { "type": "number" }
    },
    "required": ["result"]
  },
  "serialization": "json-canonical-rfc8785"
}
```

**PC-5: Declared Codebase Root**

codebaseHash MUST be computed as:

    SHA-256(merkle_root(source_tree))

dependencyHash MUST be declared separately as:

    SHA-256(canonical_serialize(dependency_manifest))

Separating source and dependency hashes allows auditors to distinguish
business logic changes from supply chain updates.

#### 3.2.2 Precondition Manifest

```json
{
  "version": "1.0",
  "erc": "XXXX",
  "preconditions": {
    "PC-1": { "satisfied": true, "interfaces_path": "/.zkagent/interfaces.json" },
    "PC-2": { "satisfied": true, "blackbox_entry_points": ["src/llm/inference.ts"] },
    "PC-3": { "satisfied": true, "state_declaration": "stateless" },
    "PC-4": { "satisfied": true, "contract_path": "/.zkagent/contract.json" },
    "PC-5": {
      "satisfied": true,
      "exclude_path": "/.zkagent/exclude.txt",
      "codebase_hash_algorithm": "sha256-merkle",
      "dependency_hash_algorithm": "sha256-canonical"
    }
  },
  "human_review_id": "0x...",
  "human_review_timestamp": 1744000000
}
```

#### 3.2.3 Precondition Verification Interface

```solidity
interface IZKPreconditionRegistry {

    struct PreconditionRecord {
        bytes32 agentId;
        bytes32 codebaseHash;
        // Bitmask: bit 0 = PC-1, ..., bit 4 = PC-5
        uint8 satisfiedPreconditions;
        address reviewer;
        uint256 reviewerStake;
        uint256 certifiedAt;
        bool challenged;
    }

    event PreconditionCertified(
        bytes32 indexed agentId,
        bytes32 indexed codebaseHash,
        address indexed reviewer,
        uint8 satisfiedPreconditions
    );

    event PreconditionChallenged(
        bytes32 indexed agentId,
        bytes32 indexed codebaseHash,
        address indexed challenger,
        uint8 disputedPrecondition
    );

    function certifyPreconditions(
        bytes32 agentId,
        bytes32 codebaseHash,
        uint8 satisfiedPreconditions,
        string calldata evidence
    ) external returns (bytes32 reviewId);

    function challengePrecondition(
        bytes32 reviewId,
        uint8 disputedPrecondition,
        string calldata evidence
    ) external;

    function isTier3Eligible(
        bytes32 agentId,
        bytes32 codebaseHash
    ) external view returns (bool eligible, bytes32 reviewId);
}
```

---

### 3.3 TLS Notary Binding

TLS Notary Binding defines how an agent proves that its external API
calls during execution were authentic and unmodified. These attestations
are stored in ExecutionLogEntry records and are critical for audit
integrity — they provide external evidence of data consumption that
cannot be retroactively deleted or altered by the agent operator.

#### 3.3.1 Protocol Overview

TLSNotary is a two-party computation (2PC) protocol. In context of
this standard, TLS attestations are captured during agent execution,
stored in off-chain execution logs, and referenced in audit proofs.

```
Agent Process (Prover)
    ↕ TLS session (standard)
External API Server
    ↕ 2PC key share protocol
Notary Server
    ↓
Attestation stored in ExecutionLogEntry.tlsAttestation
    ↓
Included in Merkle root via commitExecutionLog()
    ↓
Provable in audit ZK proof via verifyLogEntry()
```

#### 3.3.2 Attestation Structure

```solidity
struct TLSAttestation {
    string interfaceId;         // From PC-1 manifest
    string serverHostname;      // MUST match declared interface
    address notaryAddress;      // MUST be registered Notary
    bytes32 transcriptCommitment; // 2PC session commitment
    bytes selectiveDisclosureProof; // MAY be empty
    bytes32 disclosedContentHash;
    bytes notarySignature;      // EIP-712 signature
    uint256 timestamp;
}

struct TLSAttestationBundle {
    TLSAttestation[] attestations; // One per external call
    bytes32 bundleHash;
}
```

#### 3.3.3 Binding to ExecutionLogEntry

**Case A: No external calls**
```
tlsAttestation = bytes(0)
```

**Case B: External calls, full disclosure**
```
tlsAttestation = abi.encode(TLSAttestationBundle)
```

**Case C: External calls, selective disclosure**
```
tlsAttestation = abi.encode(TLSAttestationBundle)
// with selectiveDisclosureProof per attestation
```

Selective disclosure allows agents to prove data authenticity without
revealing commercially sensitive API response contents.

#### 3.3.4 Notary Registry

```solidity
interface INotaryRegistry {

    struct NotaryRecord {
        address operator;
        string endpoint;
        uint256 stake;
        bool active;
        uint256 attestationCount;
        uint256 challengeCount;
    }

    event NotaryRegistered(address indexed operator, string endpoint, uint256 stake);
    event NotarySlashed(address indexed operator, address indexed challenger, bytes32 attestationId, uint256 slashAmount);

    function registerNotary(string calldata endpoint) external payable;
    function challengeNotary(bytes32 attestationId, bytes calldata evidence) external;
    function isValidNotary(address notaryAddress) external view returns (bool);
    function getNotary(address notaryAddress) external view returns (NotaryRecord memory);
}
```

Slashable offenses:
- Notary signed attestation claiming a TLS session occurred when none did → Full stake slash
- Notary signed conflicting attestations for the same session → Full stake slash
- Notary signed attestation with commitment not matching actual session → Full stake slash

#### 3.3.5 Binding to Audit ZK Proof (Tier 3)

For Tier 3, TLS attestations are incorporated into the audit ZK circuit:

```
Public inputs:
    agentId
    codebaseHash
    periodStart / periodEnd
    executionLogRoot
    tlsCommitments[] (from all attestations in period)

Private inputs (witness):
    all ExecutionLogEntries in period
    full API response contents

Statement:
    "Agent agentId, running code codebaseHash, during
     this period, consumed data from declared endpoints
     as committed in tlsCommitments, producing outputs
     committed in executionLogRoot."
```

#### 3.3.6 Validation Rules

commitExecutionLog MUST enforce for each entry's tlsAttestation:

- **R-1**: Every `interfaceId` MUST match a declared PC-1 interface
- **R-2**: Every `serverHostname` MUST match declared endpoint pattern
- **R-3**: `notaryAddress` MUST be active in `INotaryRegistry`
- **R-4**: `notarySignature` MUST be valid EIP-712 from `notaryAddress`
- **R-5**: `timestamp` MUST be within `MAX_ATTESTATION_AGE`
- **R-6**: `transcriptCommitment` MUST NOT have been used previously

```solidity
mapping(bytes32 => bool) public usedCommitments;
```

#### 3.3.7 Notary Decentralization Path

Agents MAY declare a minimum Notary threshold in their PC-1 manifest:

```json
{
  "notary_policy": {
    "threshold": 2,
    "minimum_notaries": 3
  }
}
```

---

### 3.4 Human Review Layer

The Human Review Layer is a crowd-sourced network of staked reviewers
responsible for:

1. Certifying that agent codebases satisfy ZK Preconditions (enabling
   Tier 3 audit proof generation)
2. Certifying completed audit reports (attesting that audit proofs
   correctly represent agent execution history)

#### 3.4.1 Reviewer Lifecycle

```
Register + Stake
    ↓
Accept review assignment
    ↓
Submit certification (off-chain analysis)
    ↓
Optimistic challenge window
    ↓
    ├── No challenge → Certification valid → Reviewer earns reward
    └── Challenge → Arbitration
            ├── Challenge succeeds → Reviewer slashed
            └── Challenge fails → Challenger slashed
```

#### 3.4.2 Reviewer Registry Interface

```solidity
interface IReviewerRegistry {

    struct ReviewerRecord {
        address reviewer;
        uint256 stake;
        uint256 reviewCount;
        uint256 slashCount;
        uint8 reputationScore;
        bool active;
        string[] domains;
    }

    event ReviewerRegistered(address indexed reviewer, uint256 stake, string[] domains);
    event ReviewerSlashed(address indexed reviewer, address indexed challenger, bytes32 reviewId, uint256 slashAmount);
    event ReputationUpdated(address indexed reviewer, uint8 oldScore, uint8 newScore);

    function registerReviewer(string[] calldata domains) external payable;
    function addStake() external payable;
    function initiateWithdrawal() external;
    function completeWithdrawal() external;
    function getReviewer(address reviewer) external view returns (ReviewerRecord memory);
    function isEligible(address reviewer, bytes32 requestId) external view returns (bool);
}
```

#### 3.4.3 Review Request Lifecycle

```solidity
interface IReviewRequest {

    enum ReviewStatus {
        Pending, Assigned, Submitted, Challenged, Valid, Invalidated
    }

    struct ReviewRequest {
        bytes32 agentId;
        bytes32 codebaseHash;   // For Precondition review
        bytes32 auditId;        // For Audit report review (MAY be 0)
        string codebaseCID;
        uint8 requestedPreconditions;
        uint256 reviewFee;
        address assignedReviewer;
        ReviewStatus status;
        uint256 submittedAt;
        uint256 assignedAt;
        uint256 challengeDeadline;
        uint8 requiredReviewers;
    }

    struct ReviewCertification {
        bytes32 requestId;
        address reviewer;
        uint8 certifiedPreconditions;
        string reportCID;
        bytes reviewerSignature;
        uint256 certifiedAt;
    }

    event ReviewRequested(bytes32 indexed requestId, bytes32 indexed agentId, bytes32 codebaseHash, uint256 reviewFee);
    event ReviewAssigned(bytes32 indexed requestId, address indexed reviewer);
    event ReviewCertified(bytes32 indexed requestId, address indexed reviewer, uint8 certifiedPreconditions, string reportCID);
    event ReviewChallenged(bytes32 indexed requestId, address indexed challenger, uint8 disputedPrecondition, string evidenceCID);

    function requestReview(bytes32 agentId, bytes32 codebaseHash, string calldata codebaseCID, uint8 requestedPreconditions, uint8 requiredReviewers) external payable returns (bytes32 requestId);
    function acceptReview(bytes32 requestId) external;
    function submitCertification(bytes32 requestId, uint8 certifiedPreconditions, string calldata reportCID, bytes calldata reviewerSignature) external;
    function challengeCertification(bytes32 requestId, uint8 disputedPrecondition, string calldata evidenceCID) external payable;
    function finalizeReview(bytes32 requestId) external;
    function enforceTimeout(bytes32 requestId) external;
    function getRequest(bytes32 requestId) external view returns (ReviewRequest memory);
    function getCertification(bytes32 requestId) external view returns (ReviewCertification memory);
}
```

#### 3.4.4 Arbitration

```solidity
interface IArbitration {

    enum ArbitrationResult { Pending, ChallengeSucceeds, ChallengeFails }

    struct ArbitrationCase {
        bytes32 requestId;
        uint8 disputedPrecondition;
        address challenger;
        address reviewer;
        string challengeEvidenceCID;
        string rebuttalCID;
        ArbitrationResult result;
        uint256 resolvedAt;
    }

    event ArbitrationOpened(bytes32 indexed caseId, bytes32 indexed requestId, address challenger, address reviewer);
    event RebuttalSubmitted(bytes32 indexed caseId, address indexed reviewer, string rebuttalCID);
    event ArbitrationResolved(bytes32 indexed caseId, ArbitrationResult result);

    function openCase(bytes32 requestId, uint8 disputedPrecondition, address challenger, address reviewer, string calldata challengeEvidenceCID) external returns (bytes32 caseId);
    function submitRebuttal(bytes32 caseId, string calldata rebuttalCID) external;
    function resolveCase(bytes32 caseId) external;
    function getCase(bytes32 caseId) external view returns (ArbitrationCase memory);
}
```

#### 3.4.5 Slashing Parameters

| Parameter | Recommended Value | Description |
|---|---|---|
| `MIN_REVIEWER_STAKE` | 1000 tokens | Minimum stake to register |
| `CHALLENGE_STAKE` | 100 tokens | Stake required to challenge |
| `REVIEW_TIMEOUT` | 50400 blocks (~7 days) | Max blocks to certify |
| `CHALLENGE_PERIOD` | 50400 blocks (~7 days) | Window to challenge |
| `SLASH_REVIEWER_RATE` | 0.3 (30%) | Fraction slashed on success |
| `SLASH_CHALLENGER_RATE` | 1.0 (100%) | Fraction slashed on failure |
| `REWARD_REVIEWER_RATE` | 0.5 (50%) | Fraction awarded to reviewer |
| `REPUTATION_DECAY` | 10 points | Score reduction per slash |

#### 3.4.6 Review Report Standard

```json
{
  "version": "1.0",
  "erc": "XXXX",
  "request_id": "0x...",
  "agent_id": "0x...",
  "codebase_hash": "0x...",
  "reviewer": "0x...",
  "certified_at": 1744000000,
  "preconditions": {
    "PC-1": { "certified": true, "finding": "interfaces.json present and complete.", "evidence_files": ["src/http/client.ts", ".zkagent/interfaces.json"] },
    "PC-2": { "certified": true, "finding": "LLM inference isolated at src/llm/inference.ts.", "blackbox_entry_points": ["src/llm/inference.ts"], "evidence_files": ["src/llm/inference.ts"] },
    "PC-3": { "certified": true, "finding": "No global mutable state.", "evidence_files": ["src/state/index.ts"] },
    "PC-4": { "certified": true, "finding": "contract.json present. RFC8785 serialization.", "evidence_files": [".zkagent/contract.json"] },
    "PC-5": { "certified": true, "finding": "codebase_hash verified.", "computed_codebase_hash": "0x...", "computed_dependency_hash": "0x..." }
  },
  "overall_finding": "All five ZK Preconditions satisfied.",
  "reviewer_signature": "0x..."
}
```

#### 3.4.7 Multi-Reviewer Threshold (Optional)

For high-value audit certifications, operators MAY require M-of-N
reviewer consensus where M MUST be >= ceil(2N/3).

---

### 3.5 Recursive Proof Aggregation

Recursive Proof Aggregation defines how individual ExecutionLogEntries
across an audit period are compressed into a single proof covering the
entire period, and how multi-agent pipeline audit trails are aggregated.

This section applies to Tier 3 agents. Tier 1 and Tier 2 agents still
produce ExecutionCommitments but MAY leave auditProof empty.

#### 3.5.1 Aggregation Model

The aggregation scheme follows the IVC model from Nova
(Kothapalli and Setty, CRYPTO 2022):

```
Entry 0: π₀ = prove(agentId, codebaseHash, input₀, output₀, tls₀)
Entry 1: π₁ = fold(π₀, prove(..., input₁, output₁, tls₁))
Entry i: πᵢ = fold(πᵢ₋₁, prove(...))
Final:   π_audit = compress(π_N) → single proof for entire period
```

#### 3.5.2 Audit Period Integrity Constraint

The circuit proves that all entries in the committed period are
accounted for and none are omitted:

```
Public inputs:
    agentId
    codebaseHash
    periodStart / periodEnd
    executionLogRoot (committed on-chain)
    tlsCommitments[] (all attestations in period)

Constraint:
    Merkle root of all proven entries
    MUST equal executionLogRoot

Missing entries cannot be hidden —
any gap between tlsCommitments and
proven entries is detectable
```

This is the key audit integrity property: TLS attestations create
external evidence that is committed independently of the execution log.
If an agent omits entries from the log, the mismatch between TLS
commitments and log entries is provable.

#### 3.5.3 Aggregated Proof Interface

```solidity
interface IProofAggregator {

    struct PeriodProof {
        bytes32 agentId;
        bytes32 commitmentId;
        bytes32 codebaseHash;
        uint256 periodStart;
        uint256 periodEnd;
        bytes32[] tlsCommitments;
        bytes foldedInstance;
    }

    struct AggregatedAuditProof {
        bytes32 commitmentId;
        uint256 entryCount;
        bytes compressedProof;
        bytes publicInputs;
        bytes32 verificationKeyId;
    }

    event PeriodFolded(bytes32 indexed commitmentId, uint256 entryCount);
    event AuditProofAggregated(bytes32 indexed commitmentId, bytes32 proofHash);

    function foldEntry(PeriodProof calldata proof) external returns (bytes memory foldedInstance);
    function compressAuditProof(bytes32 commitmentId) external returns (AggregatedAuditProof memory);
    function verifyAuditProof(AggregatedAuditProof calldata proof) external view returns (bool valid);
    function getVerifier(bytes32 verificationKeyId) external view returns (address verifierContract);
}
```

#### 3.5.4 Verifier Contract Registry

```solidity
interface IVerifierRegistry {

    struct VerifierRecord {
        string circuitVersion;
        address verifierContract;
        bool active;
        uint256 deployedAt;
        bytes32 verificationKeyHash;
    }

    event VerifierDeployed(bytes32 indexed verificationKeyId, string circuitVersion, address verifierContract);
    event VerifierDeprecated(bytes32 indexed verificationKeyId, string reason);

    /// @dev MUST only be callable by governance
    function registerVerifier(string calldata circuitVersion, address verifierContract, bytes32 verificationKeyHash) external returns (bytes32 verificationKeyId);

    /// @dev MUST NOT invalidate existing certified audits
    function deprecateVerifier(bytes32 verificationKeyId, string calldata reason) external;

    function getActiveVerifier(string calldata circuitVersion) external view returns (VerifierRecord memory);
    function verify(bytes32 verificationKeyId, bytes calldata proof, bytes calldata publicInputs) external view returns (bool);
}
```

#### 3.5.5 Proof Generation Reference

| Library | Use Case |
|---|---|
| [Nova](https://github.com/microsoft/Nova) | Entry accumulation (folding) |
| [HyperNova](https://eprint.iacr.org/2023/573) | Periods with varying entry complexity |
| [Spartan](https://github.com/microsoft/Spartan) | Final compression (no trusted setup) |
| [SP1](https://github.com/succinctlabs/sp1) | General computation zkVM |

Implementations using Groth16 MUST conduct an MPC ceremony and
publish the transcript.

#### 3.5.6 Partial Period Verification

```solidity
enum AuditVerificationMode {
    EntryByEntry,      // Tier 1/2: Merkle proof per entry
    PartialAggregate,  // Mixed tiers: segment proofs
    FullAggregate      // Tier 3: single compressed proof
}

struct AuditVerificationResult {
    bytes32 commitmentId;
    AuditVerificationMode mode;
    bytes[] segmentProofs;
    uint8[] entryTiers;
    uint8 minimumTier;
}
```

#### 3.5.7 Aggregation Constraints

- **C-1**: Entries MUST be folded in chronological order
- **C-2**: Merkle root of folded entries MUST equal committed `executionLogRoot`
- **C-3**: `agentId` and `codebaseHash` MUST match active CodeRecord
- **C-4**: `tlsCommitments` count MUST equal declared PC-1 calls for each entry
- **C-5**: `verificationKeyId` MUST reference an active verifier
- **C-6**: `compressAuditProof` MUST revert if any entry is missing

---

## Rationale

### 4.1 Why Extend ERC-8126 Rather Than Define a New Registry

ERC-8126 already solves agent identity, registration deduplication,
x402 payment integration, and the crypto-economic staking framework.
This standard adds an execution audit layer on top of the existing
identity layer. The relationship is analogous to how ERC-4626 extended
ERC-20.

### 4.2 Why Periodic Commitment Rather Than Per-Call On-Chain Submission

Per-call on-chain submission would make audit trails prohibitively
expensive for high-frequency agents. Periodic Merkle root commitment
reduces on-chain costs to a fixed overhead regardless of execution
frequency, while preserving the ability to prove any individual
execution within the committed period.

A 30-day audit period with 10,000 executions requires only one
on-chain transaction for the commitment. The full audit proof is
generated on demand when an audit is requested, not continuously.

### 4.3 Why ZK Preconditions Rather Than Full Code Provability

Full provability would exclude LLM-based agents entirely. ZK
Preconditions isolate non-deterministic components behind declared
black-box boundaries (PC-2) and prove everything outside those
boundaries. The unprovable region is minimized to genuinely
non-deterministic components. The `IVerificationHook` interface allows
future zkML proofs for the black-box region without modifying this
standard.

### 4.4 Why TLS Notary Rather Than Trusted Oracles

TLS Notary creates external evidence of data consumption during
execution that cannot be retroactively modified by the agent operator.
This is critical for audit integrity: an operator cannot selectively
omit execution entries from the log without the omission being
detectable through the mismatch between TLS commitments and log entries.

Oracle networks do not provide this property — they report data at
query time but do not attest to what data a specific agent consumed
during a specific execution.

### 4.5 Why Human Review for Audit Certification

Automated verification can check mathematical properties of ZK proofs
but cannot determine whether an audit report correctly characterizes
agent behavior in business terms. Human reviewers with domain expertise
can certify that the audit findings are accurate and complete.
Economic stakes ensure reviewers are accountable for their certifications.

### 4.6 Why Nova/HyperNova for Audit Proof Aggregation

Compressing a full audit period into a single proof using classical
recursive SNARKs would cost approximately 2-3M constraints per entry.
Nova's folding scheme costs approximately 10K constraints per entry —
a ~200x reduction. For a 30-day period with 10,000 entries, this
difference is between impractical and feasible.

### 4.7 Why codebaseHash and dependencyHash Are Separate

Separating source and dependency hashes allows auditors to distinguish
business logic changes from supply chain updates. Reviewers can focus
on dependency diffs for routine updates rather than full codebase review.

### 4.8 Why Optimistic Challenge Rather Than Upfront Proof

No formal verification system can automatically certify audit report
accuracy for arbitrary agent behavior. The optimistic model provides
security through economic incentives rather than formal proofs, enabling
practical deployment today while maintaining strong deterrence against
false certifications.

### 4.9 Why Extension Interfaces Are Defined in This Standard

Defining extension points in the base standard ensures future
extensions are composable without breaking changes. Future behavioral
audit standards (e.g., LLM output correctness proofs) can implement
`IVerificationHook` to integrate cleanly with this registry.

---

## Security Considerations

### 5.1 Code Registration Layer

**SC-01 [CRITICAL]: Sigstore Bundle Forgery**
`registerCodeRecord` MUST verify the bundle is valid against the
public Rekor log and certificate subject matches the caller identity.

**SC-02 [HIGH]: codebaseHash Collision**
SHA-256 provides ~2^128 collision resistance. No practical attack
exists. Governance MAY upgrade via `IVerifierRegistry` if quantum
threats become practical.

**SC-03 [HIGH]: Dependency Substitution Without Re-registration**
PC-5 separates `codebaseHash` from `dependencyHash`. Any change
MUST trigger `updateCodeRecord`. At Tier 3, both are circuit public
inputs.

### 5.2 Execution Log Integrity Layer

**SC-04 [CRITICAL]: Selective Log Omission**
An agent operator may omit execution entries from the log before
committing the Merkle root, hiding unfavorable outputs from auditors.

Mitigation:
TLS Notary attestations create external evidence of API calls that
cannot be retroactively deleted. Auditors cross-reference committed
logs against TLS attestation records. Missing entries that correspond
to known TLS sessions are a slashable offense.

Residual risk: Executions with no external calls have no external
attestation. For these, the audit trail relies on the agent operator's
honesty at Tier 1/2. Tier 3 ZK proofs provide stronger guarantees
by proving the completeness of the committed log.

**SC-05 [HIGH]: Merkle Root Manipulation**
An operator could commit a Merkle root that does not correspond to
actual execution logs, then generate selective proofs for favorable
entries only.

Mitigation:
The audit ZK circuit (Section 3.5.2) requires that the Merkle root
of all proven entries equals the committed `executionLogRoot`. Proofs
that cover only a subset of entries cannot be completed without
revealing the gap.

**SC-06 [MEDIUM]: Commitment Period Manipulation**
An operator could specify incorrect `periodStart` or `periodEnd`
to exclude entries from a commitment.

Mitigation:
TLS attestation timestamps are independently verified by Notary
servers. Auditors can detect period boundary manipulation by comparing
attestation timestamps against committed period bounds.

### 5.3 TLS Notary Layer

**SC-07 [CRITICAL]: Notary Collusion**
Multi-Notary threshold (Section 3.3.7) requires compromising
ceil(2N/3) Notaries simultaneously. Staked Notaries face full slash
on detected collusion.

**SC-08 [HIGH]: TLS Certificate Authority Compromise**
Inherited from existing internet PKI. Certificate Transparency logs
provide monitoring. This standard does not introduce this risk.

**SC-09 [MEDIUM]: Attestation Timestamp Manipulation**
The commitment nullifier set (R-6) prevents reuse regardless of
timestamp. Fresh commitments cannot be generated for stale sessions.

### 5.4 Human Review Layer

**SC-10 [CRITICAL]: Reviewer Collusion**
Review reports are public on IPFS. Any observer can challenge.
Multi-reviewer threshold requires corrupting ceil(2N/3) independent
reviewers. Serial collusion depletes stake via `SLASH_REVIEWER_RATE`
and `REPUTATION_DECAY`.

**SC-11 [HIGH]: Reviewer Stake Insufficient for Deterrence**
`MIN_REVIEWER_STAKE` SHOULD be calibrated relative to the economic
value of the audit being certified. Governance MUST adjust parameters
as agent transaction volumes increase.

**SC-12 [MEDIUM]: Review Timeout Griefing**
Timeout triggers partial stake slash. Repeated timeouts trigger
reputation decay and eventual disqualification.

### 5.5 Proof Aggregation Layer

**SC-13 [CRITICAL]: Circuit Soundness Failure**
Use reference implementations from Microsoft Research. `IVerifierRegistry`
allows governance to deprecate buggy verifiers without invalidating
previously certified audits.

**SC-14 [HIGH]: Log Completeness Bypass**
The completeness constraint (Section 3.5.2) is enforced inside the
ZK circuit, not only at the contract level. Proofs that omit entries
fail circuit verification.

**SC-15 [MEDIUM]: Verifier Contract Substitution**
`verificationKeyHash` allows any observer to verify the deployed
contract matches the declared key. Governance actions SHOULD be
subject to timelock. Verifier contracts SHOULD be immutable.

### 5.6 Cross-Cutting Considerations

**SC-16 [HIGH]: Governance Attack**
Security-critical governance actions MUST require multi-signature
authorization (recommended: 5-of-9) and timelock delay (recommended:
7 days minimum).

**SC-17 [MEDIUM]: Front-Running Registration**
`registerCodeRecord` verifies `msg.sender` is the ERC-8126
`walletAddress` or `registrantAddress`. Attackers observing the
mempool cannot front-run.

**SC-18 [LOW]: IPFS Content Availability**
Review reports and log bundles MUST be pinned by submitter and agent
operator. Critical on-chain fields are stored independently of IPFS.

### 5.7 Trust Assumption Summary

| Tier | Assumption | Type |
|---|---|---|
| T1-1 | Sigstore Fulcio CA is honest | Organizational |
| T1-2 | Rekor log is append-only | Technical |
| T1-3 | Operator correctly reports executionLogRoot | Social |
| T2-1 | Majority of staked reviewers are honest | Economic |
| T2-2 | Challenge period is sufficient | Temporal |
| T2-3 | IPFS content available during challenge | Infrastructure |
| T3-1 | ZK circuit implementation is sound | Cryptographic |
| T3-2 | Notary server(s) are honest | Economic |
| T3-3 | Nova/HyperNova/Spartan assumptions hold | Cryptographic |
| T3-4 | Verifier contract is correctly deployed | Technical |

---

## Backwards Compatibility

### 6.1 ERC-8126 Compatibility

This standard does not modify ERC-8126's existing interfaces. Agents
registered under ERC-8126 without a `CodeRecord` under this standard
operate at implicit Tier 0 (unverified). All ERC-8126 functionality
is preserved.

### 6.2 Sigstore Compatibility

Any existing Sigstore signing workflow is compatible with Tier 1
registration without modification. Existing Rekor entry URIs can
be submitted directly as the `sigstoreBundle` field.

### 6.3 ERC-8004 Compatibility

ERC-8004 deployed on Ethereum Mainnet on January 29, 2026. Its
Validation Registry defines a pluggable hook interface for independent
validator checks.

This standard's `IVerificationHook` is designed to register directly
into the ERC-8004 Validation Registry, allowing ERC-8004 consumers
to query audit certification results through the existing ERC-8004
interface without modification.

```
ERC-8004 ValidationRegistry
    → calls IVerificationHook.verify()
    → receives (bool valid, uint8 trustScore)
    → records result in ERC-8004 format
```

This composability is the primary integration path: this standard
plugs into the deployed ERC-8004 infrastructure as a specialised
execution audit provider.

### 6.4 ERC-8150 Compatibility

This standard and ERC-8150 are complementary:
- ERC-8150 proves what the agent was authorized to do
- This standard proves what the agent actually did and with what data

An `ExecutionLogEntry` and its associated `AuditPeriod` can serve
as evidence in ERC-8150 dispute resolution.

### 6.5 Future Standard Compatibility

**zkML behavioral proof standards**: Future standards MAY implement
`IVerificationHook` to add black-box region (LLM inference) proofs.
`trustTier` values above 3 are reserved for this purpose.

**Cross-chain agent standards**: `IPipelineContext` MAY be extended
to add cross-chain step attestations by a future standard.

**On-chain agent standards**: Fully on-chain agents would naturally
satisfy all ZK Preconditions. A future standard MAY define how
on-chain agents register using `contractAddress` via the extension
points defined here.

### 6.6 Regulatory Framework Alignment

This standard is designed to produce audit artifacts compatible with:

- MiFID II Article 25 (algorithmic trading audit trail requirements)
- SEC Rule 17a-4 (electronic record retention)
- GDPR Article 22 (automated decision-making documentation)
- EU AI Act Article 12 (transparency and record-keeping for
  high-risk AI systems)

Implementations targeting regulated industries SHOULD map
`AuditPeriod` records to the specific retention and format
requirements of their jurisdiction.

---

## Test Cases

Test cases are organized by component. Implementations MUST pass all
MUST tests. SHOULD tests are recommended but not required.

### 7.1 Code Registration Tests

**T-REG-01 [MUST]: Successful Tier 1 Registration**

Preconditions: Agent A registered in ERC-8126, `msg.sender == walletAddress`, valid bundle URI

Action: `registry.registerCodeRecord(A, H, H_dep, "https://rekor...")`

Expected: Returns `recordId != bytes32(0)`, `CodeRecordRegistered` emitted, `getCodeRecord(A).codebaseHash == H`, `trustTier == 1`, `superseded == false`

---

**T-REG-02 [MUST]: Unauthorized Registration Rejected**

Preconditions: `msg.sender != walletAddress` and `msg.sender != registrantAddress`

Action: `registry.registerCodeRecord(A, H, H_dep, bundle)`

Expected: Reverts with `UnauthorizedAccess`

---

**T-REG-03 [MUST]: Unregistered Agent Rejected**

Preconditions: `agentId = A` does not exist in ERC-8126

Action: `registry.registerCodeRecord(A, H, H_dep, bundle)`

Expected: Reverts with `AgentNotFound`

---

**T-REG-04 [MUST]: Invalid Sigstore Bundle Rejected**

Action: `registry.registerCodeRecord(A, H, H_dep, "not-a-valid-uri")`

Expected: Reverts with `InvalidSigstoreBundle`

---

**T-REG-05 [MUST]: Code Record Update Supersedes Previous**

Preconditions: Agent A has `codebaseHash = H1`

Action: `registry.updateCodeRecord(A, H2, H_dep2, bundle2)`

Expected: `CodeRecordSuperseded(A, H1, H2)` emitted, old `superseded == true`

---

**T-REG-06 [MUST]: Zero codebaseHash Rejected**

Action: `registry.registerCodeRecord(A, bytes32(0), H_dep, bundle)`

Expected: Reverts with `InvalidCodeHash`

---

**T-REG-07 [MUST]: Duplicate codebaseHash Rejected**

Preconditions: Agent A already has `codebaseHash = H`

Action: `registry.registerCodeRecord(A, H, H_dep, bundle)`

Expected: Reverts with `CodeHashAlreadyRegistered`

---

**T-REG-08 [MUST]: Tier 3 Registration Blocked Without Valid Review**

Preconditions: Agent A has NO valid `ReviewCertification` for `H`

Action: `registry.registerCodeRecord(A, H, H_dep, bundle)` with `trustTier = 3`

Expected: Reverts with `MissingTier3Certification`

---

### 7.2 Execution Log Commitment Tests

**T-LOG-01 [MUST]: Successful Execution Log Commitment**

Preconditions: Agent A has active CodeRecord, valid Merkle root R

Action: `registry.commitExecutionLog(A, R, 100, t0, t1, "ipfs://...")`

Expected: Returns `commitmentId`, `ExecutionLogCommitted` emitted with correct fields

---

**T-LOG-02 [MUST]: Zero Merkle Root Rejected**

Action: `registry.commitExecutionLog(A, bytes32(0), 100, t0, t1, "ipfs://...")`

Expected: Reverts with `InvalidMerkleRoot`

---

**T-LOG-03 [MUST]: Invalid Period Rejected**

Preconditions: `periodEnd <= periodStart`

Action: `registry.commitExecutionLog(A, R, 100, t1, t0, "ipfs://...")`

Expected: Reverts with `CommitmentPeriodInvalid`

---

**T-LOG-04 [MUST]: Log Entry Verification via Merkle Proof**

Preconditions: CommitmentId C contains entry E with valid Merkle proof P

Action: `registry.verifyLogEntry(C, E, P)`

Expected: Returns `true`

---

**T-LOG-05 [MUST]: Tampered Log Entry Rejected**

Preconditions: Entry E' differs from committed entry (modified outputHash)

Action: `registry.verifyLogEntry(C, E', P)`

Expected: Returns `false`

---

**T-LOG-06 [MUST]: Log Root Mismatch Slashable**

Preconditions: TLS attestations in period reference API calls not present in committed log

Action: Challenger submits evidence of missing entries

Expected: `AuditEntryChallenged` emitted, slashing initiated

---

### 7.3 Audit Request Tests

**T-AUD-01 [MUST]: Successful Audit Request**

Preconditions: CommitmentId C exists, `msg.value >= auditFee`

Action: `registry.requestAudit{value: auditFee}(C)`

Expected: Returns `auditId`, `AuditRequested` emitted

---

**T-AUD-02 [MUST]: Audit Request Below Fee Rejected**

Action: `registry.requestAudit{value: auditFee - 1}(C)`

Expected: Reverts with `InsufficientFee`

---

**T-AUD-03 [MUST]: Audit Proof Submission**

Preconditions: AuditId X exists, valid `auditProof` and `auditReportCID`

Action: `registry.submitAuditProof(X, validProof, "ipfs://...")`

Expected: `AuditProofSubmitted` emitted, `getAudit(X).auditProof` populated

---

**T-AUD-04 [MUST]: Invalid Audit Proof Rejected**

Preconditions: `auditProof` fails on-chain circuit verification

Action: `registry.submitAuditProof(X, invalidProof, "ipfs://...")`

Expected: Reverts with `InvalidAuditProof`

---

**T-AUD-05 [MUST]: Audit Certified After Human Review**

Preconditions: Valid audit proof submitted, Human Review completed successfully

Action: `reviewRequest.finalizeReview(reviewId)`

Expected: `AuditCertified` emitted, `isAuditCertified(auditId) == true`

---

### 7.4 TLS Notary Binding Tests

**T-TLS-01 [MUST]: Unregistered Notary Rejected**

Preconditions: `notaryAddress = N` not in `INotaryRegistry`

Action: `commitExecutionLog` with entry containing attestation from N

Expected: Reverts with `InvalidNotary`

---

**T-TLS-02 [MUST]: Expired Attestation Rejected**

Preconditions: `attestation.timestamp > MAX_ATTESTATION_AGE`

Action: `commitExecutionLog` with expired attestation

Expected: Reverts with `AttestationExpired`

---

**T-TLS-03 [MUST]: Replayed transcriptCommitment Rejected**

Preconditions: Commitment C used in previous log entry

Action: `commitExecutionLog` with reused C

Expected: Reverts with `CommitmentAlreadyUsed`

---

**T-TLS-04 [MUST]: Undeclared Interface Rejected**

Preconditions: PC-1 declares `["price-oracle"]`, attestation has `interfaceId = "undeclared"`

Action: `commitExecutionLog` with undeclared interface

Expected: Reverts with `UndeclaredInterface`

---

**T-TLS-05 [MUST]: Missing Attestation for Declared Interface Rejected**

Preconditions: PC-1 declares 2 interfaces, entry has only 1 attestation

Action: `commitExecutionLog` with incomplete bundle

Expected: Reverts with `MissingAttestation`

---

**T-TLS-06 [MUST]: Invalid Notary Signature Rejected**

Action: `commitExecutionLog` with bad notary signature

Expected: Reverts with `InvalidNotarySignature`

---

**T-TLS-07 [MUST]: Notary Registration Below Minimum Stake Rejected**

Action: `notaryRegistry.registerNotary{value: MIN_NOTARY_STAKE - 1}("https://...")`

Expected: Reverts with `InsufficientStake`

---

**T-TLS-08 [MUST]: Successful Notary Challenge and Slash**

Preconditions: Notary N produced provably false attestation

Action: `notaryRegistry.challengeNotary(attestationId, validEvidence)`

Expected: `NotarySlashed` emitted, `N.stake` reduced

---

**T-TLS-09 [SHOULD]: Multi-Notary Threshold Enforcement**

Preconditions: Agent declares `{threshold: 2, minimum_notaries: 3}`, entry has 1 Notary signature

Action: `commitExecutionLog` with single-Notary entry

Expected: Reverts with `InsufficientNotaryThreshold`

---

### 7.5 Human Review Layer Tests

**T-REV-01 [MUST]: Successful Review Request Submission**

Preconditions: `msg.value >= reviewFee`

Action: `reviewRequest.requestReview{value: reviewFee}(A, H, "ipfs://...", 0b00011111, 1)`

Expected: Returns `requestId`, `ReviewRequested` emitted, status `== Pending`

---

**T-REV-02 [MUST]: Review Request Below Fee Rejected**

Action: `requestReview{value: reviewFee - 1}(...)`

Expected: Reverts with `InsufficientFee`

---

**T-REV-03 [MUST]: Ineligible Reviewer Cannot Accept**

Preconditions: Reviewer R has `stake < MIN_REVIEWER_STAKE`

Action: `reviewRequest.acceptReview(requestId)` by R

Expected: Reverts with `ReviewerIneligible`

---

**T-REV-04 [MUST]: Successful Certification Submission**

Preconditions: Request in Assigned status, valid EIP-712 signature

Action: `reviewRequest.submitCertification(X, 0b00011111, "ipfs://...", sig)`

Expected: `ReviewCertified` emitted, `challengeDeadline` set

---

**T-REV-05 [MUST]: Non-Assigned Reviewer Cannot Submit**

Action: `submitCertification` by non-assigned reviewer

Expected: Reverts with `UnauthorizedReviewer`

---

**T-REV-06 [MUST]: Challenge Within Period Accepted**

Preconditions: Status `== Submitted`, within `challengeDeadline`, `msg.value >= CHALLENGE_STAKE`

Action: `challengeCertification{value: CHALLENGE_STAKE}(X, 2, "ipfs://...")`

Expected: `ReviewChallenged` emitted, `ArbitrationOpened` emitted

---

**T-REV-07 [MUST]: Challenge After Period Rejected**

Preconditions: `block.number > challengeDeadline`

Action: `challengeCertification{value: CHALLENGE_STAKE}(X, ...)`

Expected: Reverts with `ChallengePeriodExpired`

---

**T-REV-08 [MUST]: Finalize After Challenge Period**

Preconditions: No challenge, past deadline

Action: `reviewRequest.finalizeReview(X)`

Expected: Status `== Valid`, fee transferred, `isTier3Eligible(A, H) == true`

---

**T-REV-09 [MUST]: Reviewer Slash on Successful Challenge**

Expected: Stake reduced by `SLASH_REVIEWER_RATE`, reputation decayed, status `== Invalidated`

---

**T-REV-10 [MUST]: Challenger Slash on Failed Challenge**

Expected: Challenger loses `CHALLENGE_STAKE`, reviewer rewarded

---

**T-REV-11 [MUST]: Timeout Triggers Partial Slash**

Preconditions: `block.number > assignedAt + REVIEW_TIMEOUT`

Action: `reviewRequest.enforceTimeout(X)`

Expected: Partial slash, status reset to `Pending`

---

**T-REV-12 [SHOULD]: Multi-Reviewer Threshold Requires N Certifications**

Preconditions: `requiredReviewers = 3`, only 2 submitted

Action: `finalizeReview(X)`

Expected: Reverts with `InsufficientReviewers`

---

### 7.6 Proof Aggregation Tests

**T-AGG-01 [MUST]: Successful Single Entry Fold**

Action: `aggregator.foldEntry(PeriodProof{C, 0, A, H, I, O, [...], bytes(0)})`

Expected: Returns `foldedInstance != bytes(0)`, `PeriodFolded` not yet emitted

---

**T-AGG-02 [MUST]: Log Root Mismatch Detected**

Preconditions: Folded entries' Merkle root differs from `executionLogRoot`

Action: `aggregator.compressAuditProof(C)`

Expected: Reverts with `LogRootMismatch`

---

**T-AGG-03 [MUST]: Out-of-Order Entry Rejected**

Preconditions: Entry at index 2 submitted before index 1

Action: `aggregator.foldEntry(PeriodProof{index: 2, ...})`

Expected: Reverts with `StepOutOfOrder`

---

**T-AGG-04 [MUST]: Successful Audit Proof Compression**

Preconditions: All entries folded, Merkle root matches commitment

Action: `aggregator.compressAuditProof(C)`

Expected: Returns `AggregatedAuditProof`, `verifyAuditProof(proof) == true`

---

**T-AGG-05 [MUST]: Compression Rejected with Missing Entries**

Preconditions: `entryCount = 100`, only 50 folded

Action: `aggregator.compressAuditProof(C)`

Expected: Reverts with `IncompletePipeline`

---

**T-AGG-06 [MUST]: Deprecated Verifier Rejects New Proofs**

Preconditions: `verificationKeyId V` deprecated

Action: `verifierRegistry.verify(V, proof, publicInputs)`

Expected: Reverts with `VerifierDeprecated`

---

**T-AGG-07 [MUST]: Existing Certified Audits Valid After Verifier Deprecation**

Preconditions: Audit certified using deprecated verifier V

Action: `isAuditCertified(auditId)`

Expected: Returns `true` — historical certifications not invalidated

---

**T-AGG-08 [MUST]: TLS Commitment Count Must Match PC-1 Declaration**

Preconditions: Agent declares 2 external interfaces, entry has 1 TLS commitment

Action: `aggregator.foldEntry(...)`

Expected: Reverts with `TLSCommitmentCountMismatch`

---

**T-AGG-09 [SHOULD]: Partial Aggregate Mode with Mixed Tiers**

Preconditions: Commitment has Tier 3 and Tier 1 entries mixed

Action: `registry.finalizePipelineAudit(P, encode([segmentProof_tier3]))`

Expected: Finalized, `mode == PartialAggregate`, `minimumTier == 1`

---

### 7.7 Pipeline Audit Tests

**T-PIPE-01 [MUST]: Pipeline Audit Initialization**

Preconditions: Agents A, B, C all have active CodeRecords

Action: `registry.initPipelineAudit([A, B, C])`

Expected: Returns `pipelineId`, `agentIds == [A, B, C]`, `finalized == false`

---

**T-PIPE-02 [MUST]: Commitment AgentId Mismatch Rejected**

Preconditions: Pipeline `[A, B]`, commitment belongs to agent C

Action: `registry.attachPipelineCommitment(P, 1, commitmentFromC)`

Expected: Reverts with `PipelineAgentMismatch`

---

**T-PIPE-03 [MUST]: Finalized Pipeline Cannot Be Modified**

Preconditions: Pipeline P is finalized

Action: `registry.attachPipelineCommitment(P, 0, C)`

Expected: Reverts with `PipelineAlreadyFinalized`

---

**T-PIPE-04 [MUST]: Full Tier 3 Pipeline Audit End-to-End**

Preconditions: Three Tier 3 agents A, B, C with valid CodeRecords

Action sequence:
1. `initPipelineAudit([A, B, C])` → pipelineId P
2. `commitExecutionLog(A, ...)` → commitmentId C_A
3. `commitExecutionLog(B, ...)` → C_B
4. `commitExecutionLog(C, ...)` → C_C
5. `attachPipelineCommitment(P, 0, C_A)`
6. `attachPipelineCommitment(P, 1, C_B)`
7. `attachPipelineCommitment(P, 2, C_C)`
8. `requestAudit(C_A)`, `requestAudit(C_B)`, `requestAudit(C_C)`
9. Submit audit proofs for each
10. `finalizePipelineAudit(P, aggregatedProof)`

Expected: `PipelineAuditFinalized` emitted, `finalized == true`, `verifyAuditProof == true`

---

### 7.8 Extension Hook Tests

**T-HOOK-01 [MUST]: Non-Governance Cannot Register Hook**

Action: `registry.registerVerificationHook(4, someContract)` by non-governance

Expected: Reverts with `Unauthorized`

---

**T-HOOK-02 [MUST]: Hook Registered by Governance Callable**

Preconditions: Governance registers hook H for `trustTier = 4`

Expected: Audit submissions for Tier 4 agents call `IVerificationHook(H).verify()`

---

**T-HOOK-03 [MUST]: Invalid Hook Address Rejected**

Preconditions: `hookAddress` is an EOA

Action: `registry.registerVerificationHook(4, eoaAddress)`

Expected: Reverts with `InvalidHookAddress`

---

**T-HOOK-04 [SHOULD]: Pipeline Hook Called on Step Completion**

Preconditions: `IPipelineContext` hook registered

Action: `aggregator.foldEntry(...)` on pipeline with hook

Expected: `IPipelineContext(H).onStepComplete()` called

---

### 7.9 Error Code Coverage Matrix

| Error Code | Covered By |
|---|---|
| `InvalidAddress` | T-REG-02 |
| `InvalidCodeHash` | T-REG-06 |
| `AgentNotFound` | T-REG-03 |
| `UnauthorizedAccess` | T-REG-02, T-REV-05 |
| `CodeHashAlreadyRegistered` | T-REG-07 |
| `CodeHashSuperseded` | T-REG-08 |
| `InvalidSigstoreBundle` | T-REG-04 |
| `MissingTier3Certification` | T-REG-08 |
| `InvalidMerkleRoot` | T-LOG-02 |
| `CommitmentPeriodInvalid` | T-LOG-03 |
| `AuditNotFound` | T-AUD-01 |
| `InvalidAuditProof` | T-AUD-04 |
| `InvalidNotary` | T-TLS-01 |
| `AttestationExpired` | T-TLS-02 |
| `CommitmentAlreadyUsed` | T-TLS-03 |
| `UndeclaredInterface` | T-TLS-04 |
| `MissingAttestation` | T-TLS-05 |
| `InvalidNotarySignature` | T-TLS-06 |
| `InsufficientStake` | T-TLS-07 |
| `InsufficientFee` | T-REV-02 |
| `ReviewerIneligible` | T-REV-03 |
| `UnauthorizedReviewer` | T-REV-05 |
| `ChallengePeriodExpired` | T-REV-07 |
| `InsufficientReviewers` | T-REV-12 |
| `StepOutOfOrder` | T-AGG-03 |
| `IncompletePipeline` | T-AGG-05 |
| `LogRootMismatch` | T-AGG-02 |
| `TLSCommitmentCountMismatch` | T-AGG-08 |
| `PipelineAlreadyFinalized` | T-PIPE-03 |
| `PipelineAgentMismatch` | T-PIPE-02 |
| `Unauthorized` | T-HOOK-01 |
| `InvalidHookAddress` | T-HOOK-03 |
| `InsufficientNotaryThreshold` | T-TLS-09 |

---

## Known Limitations and Future Work

**1. Audit proof generation time**
Audit proofs are generated on request, not in real-time. For a 30-day
audit period with high execution frequency, proof generation may take
minutes to hours. This is acceptable for regulatory audit contexts but
unsuitable for real-time verification use cases. This standard
explicitly targets the former, not the latter.

**2. Executions without external calls**
Executions with no external API calls have no TLS Notary attestation.
For these, audit completeness relies on agent operator honesty at
Tier 1/2. Tier 3 ZK proofs provide stronger completeness guarantees
through the log root constraint, but cannot create external evidence
where none exists. Operators SHOULD be encouraged to use at least one
declared external call (e.g., a timestamp oracle) in every execution
to anchor the log entry externally.

**3. Large-scale commitment periods**
`PipelineAuditRecord` stores `agentIds[]` and `commitmentIds[]` as
dynamic arrays. At 100+ agents, on-chain gas costs scale linearly.
A future revision should compress these into Merkle roots for
fixed-size storage.

**4. Cross-chain pipeline audits**
`pipelineId` is chain-local. Pipelines spanning multiple L1/L2
networks cannot be represented as a single `PipelineAuditRecord`.
`IPipelineContext` is designed as the extension point for a future
cross-chain audit ERC.

**5. Black-box region (LLM inference)**
This standard does not audit LLM inference correctness. ZK
Preconditions isolate non-deterministic components and prove
everything around them. When zkML proof generation becomes practical,
`trustTier` values above 3 and `IVerificationHook` are reserved for
this upgrade path.

**6. Gas costs for Tier 3**
Tier 3 ZK proof generation and on-chain verification is gas-intensive
(300k–800k gas for Groth16/Spartan verifier). This standard targets
L2 deployment (Base, Arbitrum, Optimism) where calldata and
computation costs are significantly lower. Tier 3 is RECOMMENDED
only for high-value audit scenarios. Implementations SHOULD clearly
disclose gas cost expectations to operators.

Feedback is particularly welcome on items 2, 3, and 6, which are
the most likely to require design changes before Final status.

---

## Reference Implementation

A reference implementation will be provided demonstrating:

1. `IAgentAuditRegistry` deployment on Base Sepolia testnet
2. Tier 1 registration flow (Sigstore bundle + codebaseHash)
3. Execution log commitment flow (batch → Merkle root → on-chain)
4. Tier 2 Human Review flow (request → certify → challenge → finalize)
5. Tier 3 audit proof flow (ZK Precondition manifest → TLS Notary →
   Nova fold → Spartan compress → on-chain audit proof verification)
6. Three-agent pipeline audit in `PartialAggregate` mode
7. Sample regulatory audit report generation (MiFID II format)

Reference implementation: `github.com/[author]/zkagent-protocol`

Circuit implementation: Built on [Nova](https://github.com/microsoft/Nova)
and [Spartan](https://github.com/microsoft/Spartan)

TLS Notary integration: Built on [tlsn](https://github.com/tlsnotary/tlsn)

---

## Copyright

Copyright and related rights waived via [CC0](https://eips.ethereum.org/LICENSE).
