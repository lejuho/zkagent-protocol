---
eip: (TBD — assigned on PR)
title: Agent Code Integrity Verification Standard
description: A standard for runtime code integrity verification of AI agents using ZK proofs, extending ERC-8126
author: (your name/handle)
discussions-to: (Ethereum Magicians URL — create thread first)
status: Draft
type: Standards Track
category: ERC
created: 2026-04-14
requires: 8126, 712, 155
---

## Abstract

This ERC defines a standard interface for verifying
the runtime code integrity of AI agents operating in
multi-agent pipelines.

While ERC-8126 addresses agent registration and
point-in-time verification, and Sigstore addresses
build-time supply chain integrity, a gap exists between
deployment and execution: no standard currently proves
that a running agent process executes the same code
that was registered.

This standard introduces:

1. A `codebaseHash` registration extension to ERC-8126
2. A ZK-compatible agent code structure specification
   (ZK Preconditions) that enables efficient proof
   generation
3. A runtime verification interface using TLS Notary
   attestations bound to registered code hashes
4. A recursive proof aggregation pattern allowing
   multi-step pipeline execution proofs to be
   compressed into a single verifiable proof
5. A crowdsourced verifier network with
   crypto-economic slashing for the Human Review
   layer
6. An extension interface (`IVerificationHook`) allowing
   future verification methods to integrate without
   modifying this standard
7. A pipeline context interface (`IPipelineContext`)
   for multi-step execution proof aggregation

---

## Motivation

### The Gap Between Deployment and Execution

Existing standards address two points in the agent
lifecycle but leave a critical gap between them:

Sigstore and SLSA address supply chain integrity:
"This artifact was built from this source by
this identity at this time."

ERC-8126 addresses point-in-time registration:
"This agent exists and has passed these checks."

Neither addresses runtime integrity:
"The agent responding to this call right now is
executing the code that was registered."

This gap is inconsequential when an agent operator
controls both the registered identity and the
execution environment. It becomes critical when:

- Agent A calls Agent B across organizational
  boundaries (Agent B is operated by a third party)
- An agent marketplace intermediates between
  agent providers and consumers
- A multi-step pipeline depends on sequential
  agent outputs where each step's output is the
  next step's input
- Regulatory or contractual requirements mandate
  an auditable record of which code version
  produced a given output

### Why Existing Approaches Are Insufficient

**Sigstore / cosign**
Signs container images at build time. Cannot prove
that a running process was launched from a signed
image, nor that the process has not been modified
after launch. Does not address runtime state.

**ERC-8126 WAV (Web Application Verification)**
Verifies that an HTTPS endpoint is reachable and
has a valid SSL certificate. Does not verify the
code executing behind that endpoint.

**ERC-8126 PDV (Private Data Verification)**
Generates ZK proofs of verification results but
leaves the proof generation mechanism and the
definition of what constitutes "code integrity"
deliberately unspecified.

**TEE attestations (Nitro, SEV-SNP, TDX)**
Prove that code runs in a trusted hardware
environment. Require the agent operator to
provision TEE infrastructure, creating adoption
barriers. Vendor-specific trust roots (AWS, AMD,
Intel) conflict with cross-platform neutrality
requirements. Appropriate as an optional higher
trust tier, not as a baseline requirement.

### Why a New Standard Is Needed Now

Three conditions have recently converged to make
this standard both necessary and implementable:

**Condition 1: Multi-agent pipelines entering
production**
Agent-to-agent calling is moving from experimental
to production in financial automation, software
development pipelines, and legal document
processing. Each cross-organizational agent call
is a trust boundary that existing standards do
not address.

**Condition 2: ZK proof generation is now
practical**
TLSNotary provides a production-ready protocol
for proving TLS session contents without exposing
session keys. Nova/HyperNova folding schemes
reduce recursive proof aggregation costs to
practical levels for per-call verification.

**Condition 3: The standard layer is unoccupied**
ERC-8004 identifies validation as a necessary
component of trustless agents but explicitly
leaves the validation mechanism unspecified.
ERC-8126 provides the registration and
crypto-economic infrastructure but does not
define code integrity verification. This ERC
occupies the gap both standards deliberately
leave open.

### Design Goals

This standard is designed around four principles:

**Minimize trust assumptions**
Each trust assumption should be explicit,
justified, and reducible over time. Phase 1
introduces build pipeline trust (Sigstore).
Phase 2 adds crowd-sourced verifier consensus.
Phase 3 enables ZK-based trustless verification.
The standard is designed so that operators can
adopt Phase 1 immediately and upgrade trust
tiers without breaking changes.

**Minimize adoption friction**
Requiring TEE infrastructure or ZK proof
generation from day one would prevent adoption.
This standard defines a tiered trust model where
the minimum viable implementation requires only
a Sigstore-signed build pipeline and a
`codebaseHash` registration — infrastructure most
agent operators already have or can add with
minimal effort.

**Remain execution environment agnostic**
Agents run on AWS Lambda, GCP Cloud Run,
bare metal, and everything in between. This
standard makes no assumptions about the
execution environment. Verification proofs are
produced by the agent process itself, not by
the underlying infrastructure.

**Enable composability**
Multi-agent pipelines require that individual
agent proofs can be composed into pipeline-level
proofs. This standard defines the proof interface
such that individual execution proofs can be
aggregated using recursive ZK schemes without
modification to the base standard.

---

## Specification

The key words "MUST", "MUST NOT", "REQUIRED",
"SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted
as described in RFC 2119 and RFC 8174.

---

### 3.1 Interface Definitions

#### 3.1.1 Core Registry Interface

Extends ERC-8126's `IERCXXXX` interface with
code integrity fields.

```solidity
// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.0;

import "./IERC8126.sol";

interface IAgentCodeRegistry is IERC8126 {

    // ─── Structs ───────────────────────────────

    /// @notice Code integrity record for an agent
    struct CodeRecord {
        // Hash of the agent codebase at registration
        // MUST be SHA-256 of the canonical source tree
        bytes32 codebaseHash;

        // Dependency set hash
        // MUST be SHA-256 of canonical dependency manifest
        bytes32 dependencyHash;

        // Sigstore bundle URI pointing to the
        // cosign signature for this codebaseHash
        // MUST be a valid HTTPS URI
        string sigstoreBundle;

        // Trust tier at registration time
        // 1 = Sigstore only (Phase 1)
        // 2 = Crowd-sourced verifier consensus (Phase 2)
        // 3 = ZK proof verified (Phase 3)
        // 4+ = Reserved for future extension via IVerificationHook
        uint8 trustTier;

        // Block number when this record was registered
        uint256 registeredAt;

        // Whether this record has been superseded
        // by a newer version
        bool superseded;
    }

    /// @notice Runtime verification record
    /// produced per agent call
    struct VerificationRecord {
        // Agent being verified
        bytes32 agentId;

        // codebaseHash claimed at call time
        bytes32 claimedCodeHash;

        // Proof binding claimed hash to runtime
        // Format depends on trustTier:
        // Tier 1: Sigstore rekor entry hash
        // Tier 2: Verifier consensus commitment
        // Tier 3: ZK proof bytes
        bytes proof;

        // TLS Notary attestation bundle for external calls
        // made during this execution
        // MAY be empty if agent made no external calls
        bytes tlsAttestation;

        // Hash of inputs received
        bytes32 inputHash;

        // Hash of outputs produced
        bytes32 outputHash;

        // Timestamp of verification
        uint256 timestamp;

        // Trust tier used for this verification
        uint8 trustTier;

        // Verification key ID used (Tier 3 only)
        bytes32 verificationKeyId;
    }

    /// @notice Pipeline execution record
    /// aggregates multiple VerificationRecords
    struct PipelineRecord {
        // Unique pipeline execution ID
        bytes32 pipelineId;

        // Ordered list of agentIds in this pipeline
        bytes32[] agentIds;

        // Ordered list of verificationIds
        // MUST correspond 1:1 with agentIds
        bytes32[] verificationIds;

        // Aggregated recursive ZK proof
        // covering all steps
        // MAY be empty until finalized
        bytes aggregatedProof;

        // Whether pipeline is complete
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

    /// @notice Emitted when a runtime verification
    /// record is submitted
    event VerificationSubmitted(
        bytes32 indexed agentId,
        bytes32 indexed verificationId,
        bytes32 inputHash,
        bytes32 outputHash,
        uint8 trustTier
    );

    /// @notice Emitted when a verifier challenges
    /// a submitted verification record
    event VerificationChallenged(
        bytes32 indexed verificationId,
        address indexed challenger,
        bytes evidence
    );

    /// @notice Emitted when a pipeline is finalized
    event PipelineFinalized(
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
    error CodeHashMismatch();
    error CodeHashSuperseded();
    error InvalidProof();
    error InvalidInputHash();
    error InvalidOutputHash();
    error InvalidNotary();
    error AttestationExpired();
    error CommitmentAlreadyUsed();
    error UndeclaredInterface();
    error MissingAttestation();
    error InvalidNotarySignature();
    error InsufficientStake();
    error InvalidSigstoreBundle();
    error MissingTier3Certification();
    error InputOutputMismatch();
    error StepOutOfOrder();
    error IncompletePipeline();
    error AgentIdMismatch();
    error TLSCommitmentCountMismatch();
    error InvalidPipelineStep();
    error PipelineAlreadyFinalized();
    error PipelineAgentMismatch();
    error Unauthorized();
    error InvalidHookAddress();
    error InsufficientNotaryThreshold();

    // ─── Code Registration ─────────────────────

    /// @notice Register a codebaseHash for an
    /// existing ERC-8126 agent
    /// @dev MUST revert if agentId does not exist
    ///      in the ERC-8126 registry
    /// @dev MUST revert if caller is not the
    ///      walletAddress or registrantAddress
    ///      of the ERC-8126 agent record
    /// @param agentId ERC-8126 agent identifier
    /// @param codebaseHash SHA-256 of canonical
    ///        source tree
    /// @param dependencyHash SHA-256 of canonical
    ///        dependency manifest
    /// @param sigstoreBundle HTTPS URI of cosign
    ///        signature bundle
    /// @return recordId Unique identifier for
    ///         this code record
    function registerCodeRecord(
        bytes32 agentId,
        bytes32 codebaseHash,
        bytes32 dependencyHash,
        string calldata sigstoreBundle
    ) external returns (bytes32 recordId);

    /// @notice Update codebaseHash (new version)
    /// @dev Previous record MUST be marked superseded
    /// @dev MUST emit CodeRecordSuperseded
    function updateCodeRecord(
        bytes32 agentId,
        bytes32 newCodebaseHash,
        bytes32 newDependencyHash,
        string calldata newSigstoreBundle
    ) external returns (bytes32 recordId);

    /// @notice Retrieve the active code record
    ///         for an agent
    /// @dev MUST return the most recent non-superseded
    ///      record
    function getCodeRecord(
        bytes32 agentId
    ) external view returns (CodeRecord memory);

    /// @notice Retrieve code record by recordId
    function getCodeRecordById(
        bytes32 recordId
    ) external view returns (CodeRecord memory);

    // ─── Runtime Verification ──────────────────

    /// @notice Submit a runtime verification record
    /// @dev Proof format and validation logic
    ///      depends on trustTier of the agent's
    ///      current CodeRecord
    /// @dev MUST revert if claimedCodeHash does not
    ///      match the active CodeRecord for agentId
    /// @param agentId Agent being verified
    /// @param claimedCodeHash Hash agent claims
    ///        to be running
    /// @param proof Proof bytes (tier-dependent)
    /// @param tlsAttestation TLS Notary attestation
    ///        bundle (MAY be empty)
    /// @param inputHash Hash of inputs
    /// @param outputHash Hash of outputs
    /// @return verificationId Unique identifier
    function submitVerification(
        bytes32 agentId,
        bytes32 claimedCodeHash,
        bytes calldata proof,
        bytes calldata tlsAttestation,
        bytes32 inputHash,
        bytes32 outputHash
    ) external returns (bytes32 verificationId);

    /// @notice Retrieve a verification record
    function getVerification(
        bytes32 verificationId
    ) external view returns (VerificationRecord memory);

    /// @notice Check if a verification record is
    ///         currently valid (not challenged/slashed)
    function isVerificationValid(
        bytes32 verificationId
    ) external view returns (bool);

    // ─── Pipeline ──────────────────────────────

    /// @notice Initialize a new pipeline record
    /// @param agentIds Ordered list of agents
    ///        that will participate
    /// @return pipelineId
    function initPipeline(
        bytes32[] calldata agentIds
    ) external returns (bytes32 pipelineId);

    /// @notice Attach a verification record to
    ///         a pipeline step
    /// @dev stepIndex MUST match position in
    ///      agentIds array
    /// @dev MUST revert if verificationId's agentId
    ///      does not match agentIds[stepIndex]
    function attachPipelineStep(
        bytes32 pipelineId,
        uint256 stepIndex,
        bytes32 verificationId
    ) external;

    /// @notice Finalize pipeline with aggregated proof
    /// @dev MUST revert if any step is missing
    /// @dev MUST revert if any step verification
    ///      is invalid
    /// @dev aggregatedProof MAY be empty for
    ///      Tier 1 pipelines
    function finalizePipeline(
        bytes32 pipelineId,
        bytes calldata aggregatedProof
    ) external;

    /// @notice Retrieve a pipeline record
    function getPipeline(
        bytes32 pipelineId
    ) external view returns (PipelineRecord memory);

    // ─── Extension Hooks ───────────────────────

    /// @notice Register a custom verification hook
    ///         for a specific trust tier
    /// @dev Allows future verification methods
    ///      without modifying this standard
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
/// @notice Interface for pluggable verification
///         methods (future trust tiers)
interface IVerificationHook {

    /// @notice Validate a proof for a given agent
    ///         and claimed code hash
    /// @param agentId Agent being verified
    /// @param claimedCodeHash Hash agent claims
    /// @param proof Proof bytes
    /// @param context Arbitrary context data
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

    /// @notice Return the trust tier this hook implements
    function trustTier() external view returns (uint8);

    /// @notice Return human-readable description
    function description() external view returns (string memory);
}
```

#### 3.1.3 Pipeline Context Hook Interface

```solidity
/// @notice Interface for pipeline-level hooks
///         called at each step completion
interface IPipelineContext {

    /// @notice Called when a pipeline step completes
    /// @param pipelineId Pipeline identifier
    /// @param stepIndex Step index (0-based)
    /// @param agentId Agent that completed the step
    /// @param outputHash Hash of step output
    /// @param proof Step-level proof
    function onStepComplete(
        bytes32 pipelineId,
        uint256 stepIndex,
        bytes32 agentId,
        bytes32 outputHash,
        bytes calldata proof
    ) external;

    /// @notice Called when a pipeline is finalized
    /// @param pipelineId Pipeline identifier
    /// @param aggregatedProof Final aggregated proof
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

    /// @notice Evaluate whether evidence warrants slashing
    /// @param agentId Agent being evaluated
    /// @param verificationId Disputed verification
    /// @param evidence Bytes encoding the dispute evidence
    /// @return shouldSlash Whether to slash
    /// @return slashAmount Token amount to slash
    /// @return reason Human-readable reason
    function evaluate(
        bytes32 agentId,
        bytes32 verificationId,
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

ZK Preconditions define the structural requirements
that agent code MUST satisfy to be eligible for
Tier 3 (ZK proof) verification.

The motivation for preconditions is as follows:
arbitrary code is not efficiently provable in ZK
circuits. By constraining the structure of agent
code at registration time, proof generation becomes
tractable without requiring the prover to encode
unbounded non-determinism.

Agents that do not satisfy ZK Preconditions MAY
still register and operate at Tier 1 or Tier 2.
ZK Preconditions are a requirement only for
Tier 3 trust claims.

The Human Review Layer (Section 3.4) is responsible
for certifying that a submitted codebase satisfies
ZK Preconditions before a Tier 3 CodeRecord
can be registered.

#### 3.2.1 Precondition Definitions

An agent codebase is ZK-compatible if and only if
it satisfies all five of the following preconditions.

**PC-1: Declared External Interface**

All external calls (HTTP, RPC, database, other
agent APIs) MUST be declared in a machine-readable
interface manifest at a canonical path within
the repository:

    /.zkagent/interfaces.json

The manifest MUST enumerate:
- Each external endpoint (URL pattern or service identifier)
- The expected input schema (JSON Schema)
- The expected output schema (JSON Schema)
- Whether the call is deterministic or non-deterministic

Calls to undeclared endpoints MUST cause the
agent runtime to halt with a declared error.

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
        "properties": {
          "symbol": { "type": "string" }
        }
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

Non-deterministic components (LLM inference,
random number generation, time-dependent logic)
MUST be isolated behind a single declared entry
point per component type.

The isolation boundary MUST satisfy:
- The entry point takes only serializable inputs
- The entry point produces only serializable outputs
- No non-deterministic component MAY read from
  or write to shared mutable state outside its declared scope
- Side effects MUST be limited to the output value
  returned through the entry point

```
Agent execution model:

┌─────────────────────────────────────────┐
│  Provable Region (ZK circuit covers)    │
│                                         │
│  input parsing                          │
│  routing logic                          │
│  output formatting                      │
│  ┌───────────────────────────────────┐  │
│  │  Black-box Region                 │  │
│  │  (ZK circuit excludes)            │  │
│  │                                   │  │
│  │  LLM inference entry point        │  │
│  │  RNG entry point                  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**PC-3: No Global Mutable State**

The agent MUST NOT read from or write to mutable
state that persists across invocations and is
not passed explicitly as input.

Permitted state patterns:
- Input passed explicitly in the invocation payload
- State returned explicitly in the invocation output
- Read-only configuration loaded at startup from a
  declared configuration file

Prohibited state patterns:
- In-process global variables modified across invocations
- Shared database writes not reflected in the output hash
- File system writes to undeclared paths
- Cache writes that affect determinism of subsequent invocations

**PC-4: Explicit Input/Output Contract**

The agent MUST expose a typed invocation interface with:
- A declared input type (JSON Schema or equivalent)
- A declared output type (JSON Schema or equivalent)
- A canonical serialization format for both

These declarations MUST be present at:

    /.zkagent/contract.json

The `inputHash` and `outputHash` fields of
`VerificationRecord` MUST be computed as:

    SHA-256(canonical_serialize(input))
    SHA-256(canonical_serialize(output))

where `canonical_serialize` is deterministic
across all implementations for the same logical value.

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
      "confidence": { "type": "number" },
      "sources": { "type": "array" }
    },
    "required": ["result"]
  },
  "serialization": "json-canonical-rfc8785"
}
```

**PC-5: Declared Codebase Root**

The `codebaseHash` registered in Section 3.1 MUST be
computed as:

    SHA-256(merkle_root(source_tree))

where `source_tree` is the canonical file tree of
the agent repository, excluding:
- Build artifacts
- Dependency lock files (listed separately)
- Files matching patterns in `/.zkagent/exclude.txt`

The dependency set MUST be declared separately as:

    SHA-256(canonical_serialize(dependency_manifest))

and stored as `dependencyHash` alongside `codebaseHash`
in the `CodeRecord`.

#### 3.2.2 Precondition Manifest

Agents claiming ZK Precondition compliance MUST
include a precondition manifest at:

    /.zkagent/preconditions.json

```json
{
  "version": "1.0",
  "erc": "XXXX",
  "preconditions": {
    "PC-1": {
      "satisfied": true,
      "interfaces_path": "/.zkagent/interfaces.json"
    },
    "PC-2": {
      "satisfied": true,
      "blackbox_entry_points": [
        "src/llm/inference.ts",
        "src/utils/rng.ts"
      ]
    },
    "PC-3": {
      "satisfied": true,
      "state_declaration": "stateless"
    },
    "PC-4": {
      "satisfied": true,
      "contract_path": "/.zkagent/contract.json"
    },
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
        // Bitmask: bit 0 = PC-1, bit 1 = PC-2, ...
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

    /// @notice Submit a precondition certification
    /// @dev Caller MUST have sufficient stake
    function certifyPreconditions(
        bytes32 agentId,
        bytes32 codebaseHash,
        uint8 satisfiedPreconditions,
        string calldata evidence
    ) external returns (bytes32 reviewId);

    /// @notice Challenge a precondition certification
    function challengePrecondition(
        bytes32 reviewId,
        uint8 disputedPrecondition,
        string calldata evidence
    ) external;

    /// @notice Check if an agent is Tier 3 eligible
    function isTier3Eligible(
        bytes32 agentId,
        bytes32 codebaseHash
    ) external view returns (
        bool eligible,
        bytes32 reviewId
    );
}
```

---

### 3.3 TLS Notary Binding

TLS Notary Binding defines how an agent proves
that its external API calls during execution
were authentic and unmodified.

#### 3.3.1 Protocol Overview

TLSNotary is a two-party computation (2PC)
protocol. The three parties in context of this standard:

```
Agent Process (Prover)
    ↕ TLS session (standard)
External API Server
    ↕ 2PC key share protocol
Notary Server
    ↓
Attestation
    ↓
IAgentCodeRegistry.submitVerification()
```

The Notary attests that:
1. A TLS session occurred with the declared server
2. The transcript commitment is bound to the session keys
3. The Prover holds the session keys

#### 3.3.2 Attestation Structure

```solidity
struct TLSAttestation {
    string interfaceId;
    string serverHostname;
    address notaryAddress;
    bytes32 transcriptCommitment;
    bytes selectiveDisclosureProof;
    bytes32 disclosedContentHash;
    bytes notarySignature;
    uint256 timestamp;
}

struct TLSAttestationBundle {
    TLSAttestation[] attestations;
    bytes32 bundleHash;
}
```

#### 3.3.3 Binding to VerificationRecord

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
// with selectiveDisclosureProof populated per attestation
```

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

    event NotaryRegistered(
        address indexed operator,
        string endpoint,
        uint256 stake
    );

    event NotarySlashed(
        address indexed operator,
        address indexed challenger,
        bytes32 attestationId,
        uint256 slashAmount
    );

    function registerNotary(
        string calldata endpoint
    ) external payable;

    function challengeNotary(
        bytes32 attestationId,
        bytes calldata evidence
    ) external;

    function isValidNotary(
        address notaryAddress
    ) external view returns (bool);

    function getNotary(
        address notaryAddress
    ) external view returns (NotaryRecord memory);
}
```

Slashable offenses:
- Notary signed an attestation claiming a TLS session occurred when none did → Full stake slash
- Notary signed two conflicting attestations for the same session → Full stake slash
- Notary signed an attestation with a commitment that does not match the actual session transcript → Full stake slash

#### 3.3.5 Binding to ZK Proof (Tier 3)

For Tier 3, TLS attestations are incorporated into
the ZK proof circuit:

```
Public inputs:
    agentId
    codebaseHash
    inputHash
    outputHash
    transcriptCommitment
    notaryAddress

Private inputs (witness):
    full API response contents
    agent execution trace

Statement:
    "I executed the code with hash codebaseHash.
     I received a response from the server committed
     in transcriptCommitment. Given these inputs and
     this response, I produced outputHash."
```

#### 3.3.6 Validation Rules

`submitVerification` MUST enforce:

- **R-1**: Every `interfaceId` in attestations MUST match a declared interface in PC-1 manifest
- **R-2**: Every `serverHostname` MUST match the endpoint pattern of the declared interface
- **R-3**: `notaryAddress` MUST be a valid active Notary in `INotaryRegistry`
- **R-4**: `notarySignature` MUST be a valid EIP-712 signature from `notaryAddress`
- **R-5**: `timestamp` MUST be within `MAX_ATTESTATION_AGE` of `block.timestamp` (recommended: 300 seconds)
- **R-6**: `transcriptCommitment` MUST NOT have been used in a previous `VerificationRecord`

```solidity
mapping(bytes32 => bool) public usedCommitments;

// In submitVerification:
require(
    !usedCommitments[attestation.transcriptCommitment],
    "Commitment already used"
);
usedCommitments[attestation.transcriptCommitment] = true;
```

#### 3.3.7 Notary Decentralization Path

Agents MAY declare a minimum Notary threshold in
their PC-1 manifest:

```json
{
  "notary_policy": {
    "threshold": 2,
    "minimum_notaries": 3
  }
}
```

Agents declaring a threshold policy MUST submit
attestations signed by at least `threshold` distinct
Notaries. `submitVerification` MUST enforce this.

---

### 3.4 Human Review Layer

The Human Review Layer is a crowd-sourced network
of staked reviewers responsible for certifying that
agent codebases satisfy ZK Preconditions before a
Tier 3 CodeRecord can be registered.

#### 3.4.1 Reviewer Lifecycle

```
Register + Stake
    ↓
Assigned review request
    ↓
Submit certification (off-chain analysis)
    ↓
Optimistic window (challenge period)
    ↓
    ├── No challenge → Certification valid
    │       → Reviewer earns reward
    │
    └── Challenge submitted
            ↓
        Arbitration
            ↓
            ├── Challenge succeeds
            │       → Reviewer slashed
            │       → Challenger rewarded
            │
            └── Challenge fails
                    → Challenger slashed
                    → Reviewer rewarded
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

    event ReviewerRegistered(
        address indexed reviewer,
        uint256 stake,
        string[] domains
    );

    event ReviewerSlashed(
        address indexed reviewer,
        address indexed challenger,
        bytes32 reviewId,
        uint256 slashAmount
    );

    event ReputationUpdated(
        address indexed reviewer,
        uint8 oldScore,
        uint8 newScore
    );

    function registerReviewer(
        string[] calldata domains
    ) external payable;

    function addStake() external payable;

    function initiateWithdrawal() external;

    function completeWithdrawal() external;

    function getReviewer(
        address reviewer
    ) external view returns (ReviewerRecord memory);

    function isEligible(
        address reviewer,
        bytes32 requestId
    ) external view returns (bool);
}
```

#### 3.4.3 Review Request Lifecycle

```solidity
interface IReviewRequest {

    enum ReviewStatus {
        Pending,
        Assigned,
        Submitted,
        Challenged,
        Valid,
        Invalidated
    }

    struct ReviewRequest {
        bytes32 agentId;
        bytes32 codebaseHash;
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

    event ReviewRequested(
        bytes32 indexed requestId,
        bytes32 indexed agentId,
        bytes32 codebaseHash,
        uint256 reviewFee
    );

    event ReviewAssigned(
        bytes32 indexed requestId,
        address indexed reviewer
    );

    event ReviewCertified(
        bytes32 indexed requestId,
        address indexed reviewer,
        uint8 certifiedPreconditions,
        string reportCID
    );

    event ReviewChallenged(
        bytes32 indexed requestId,
        address indexed challenger,
        uint8 disputedPrecondition,
        string evidenceCID
    );

    function requestReview(
        bytes32 agentId,
        bytes32 codebaseHash,
        string calldata codebaseCID,
        uint8 requestedPreconditions,
        uint8 requiredReviewers
    ) external payable returns (bytes32 requestId);

    function acceptReview(bytes32 requestId) external;

    function submitCertification(
        bytes32 requestId,
        uint8 certifiedPreconditions,
        string calldata reportCID,
        bytes calldata reviewerSignature
    ) external;

    function challengeCertification(
        bytes32 requestId,
        uint8 disputedPrecondition,
        string calldata evidenceCID
    ) external payable;

    function finalizeReview(bytes32 requestId) external;

    function enforceTimeout(bytes32 requestId) external;

    function getRequest(
        bytes32 requestId
    ) external view returns (ReviewRequest memory);

    function getCertification(
        bytes32 requestId
    ) external view returns (ReviewCertification memory);
}
```

#### 3.4.4 Arbitration

```solidity
interface IArbitration {

    enum ArbitrationResult {
        Pending,
        ChallengeSucceeds,
        ChallengeFails
    }

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

    event ArbitrationOpened(
        bytes32 indexed caseId,
        bytes32 indexed requestId,
        address challenger,
        address reviewer
    );

    event RebuttalSubmitted(
        bytes32 indexed caseId,
        address indexed reviewer,
        string rebuttalCID
    );

    event ArbitrationResolved(
        bytes32 indexed caseId,
        ArbitrationResult result
    );

    function openCase(
        bytes32 requestId,
        uint8 disputedPrecondition,
        address challenger,
        address reviewer,
        string calldata challengeEvidenceCID
    ) external returns (bytes32 caseId);

    function submitRebuttal(
        bytes32 caseId,
        string calldata rebuttalCID
    ) external;

    function resolveCase(bytes32 caseId) external;

    function getCase(
        bytes32 caseId
    ) external view returns (ArbitrationCase memory);
}
```

#### 3.4.5 Slashing Parameters

| Parameter | Recommended Value | Description |
|---|---|---|
| `MIN_REVIEWER_STAKE` | 1000 tokens | Minimum stake to register |
| `CHALLENGE_STAKE` | 100 tokens | Stake required to open a challenge |
| `REVIEW_TIMEOUT` | 50400 blocks (~7 days) | Max blocks to submit after accepting |
| `CHALLENGE_PERIOD` | 50400 blocks (~7 days) | Window to challenge after submission |
| `SLASH_REVIEWER_RATE` | 0.3 (30%) | Fraction slashed on successful challenge |
| `SLASH_CHALLENGER_RATE` | 1.0 (100%) | Fraction slashed on failed challenge |
| `REWARD_REVIEWER_RATE` | 0.5 (50%) | Fraction of slash awarded to reviewer |
| `REPUTATION_DECAY` | 10 points | Score reduction per successful challenge |

#### 3.4.6 Review Report Standard

Review reports stored as IPFS CIDs MUST follow this structure:

```json
{
  "version": "1.0",
  "erc": "XXXX",
  "request_id": "0x...",
  "agent_id": "0x...",
  "codebase_hash": "0x...",
  "codebase_cid": "ipfs://...",
  "reviewer": "0x...",
  "certified_at": 1744000000,
  "preconditions": {
    "PC-1": {
      "certified": true,
      "finding": "interfaces.json present and complete. All external calls declared.",
      "evidence_files": ["src/http/client.ts", ".zkagent/interfaces.json"]
    },
    "PC-2": {
      "certified": true,
      "finding": "LLM inference isolated at src/llm/inference.ts.",
      "blackbox_entry_points": ["src/llm/inference.ts"],
      "evidence_files": ["src/llm/inference.ts", "src/router.ts"]
    },
    "PC-3": {
      "certified": true,
      "finding": "No global variables mutated across invocations.",
      "evidence_files": ["src/state/index.ts"]
    },
    "PC-4": {
      "certified": true,
      "finding": "contract.json present. Serialization uses RFC8785.",
      "evidence_files": [".zkagent/contract.json", "src/io/serialize.ts"]
    },
    "PC-5": {
      "certified": true,
      "finding": "codebase_hash verified against SHA-256 merkle root.",
      "computed_codebase_hash": "0x...",
      "computed_dependency_hash": "0x..."
    }
  },
  "overall_finding": "All five ZK Preconditions satisfied.",
  "reviewer_signature": "0x..."
}
```

#### 3.4.7 Multi-Reviewer Threshold (Optional)

For high-value agents, operators MAY require M-of-N
reviewer consensus where M MUST be >= ceil(2N/3).

---

### 3.5 Recursive Proof Aggregation

Recursive Proof Aggregation defines how individual
`VerificationRecord`s from multiple agents in a
pipeline are compressed into a single proof.

This section applies only to Tier 3 agents. Tier 1
and Tier 2 pipelines MUST still produce
`PipelineRecord`s but MAY leave `aggregatedProof` empty.

#### 3.5.1 Aggregation Model

The aggregation scheme follows the Incrementally
Verifiable Computation (IVC) model from Nova
(Kothapalli and Setty, CRYPTO 2022):

```
Step 0: π₀ = prove(agentId_0, codebaseHash_0, input_0, output_0, tlsCommitments_0)
Step 1: π₁ = fold(π₀, prove(agentId_1, ..., input_1, output_1, ...))
         where input_1 MUST equal output_0
Step i: πᵢ = fold(πᵢ₋₁, prove(...))
Final:  π_final = compress(π_N) → single constant-size proof
```

#### 3.5.2 Step Transition Constraint

The critical invariant:

```
inputHash_i == outputHash_(i-1)  for all i > 0
```

This constraint MUST be enforced inside the ZK
circuit, not only at the smart contract level.

Circuit public inputs for step i:

```
agentId_i
codebaseHash_i
inputHash_i
outputHash_i
outputHash_(i-1)
tlsCommitment_i
pipelineId
stepIndex_i

constraint: inputHash_i == outputHash_(i-1)
```

#### 3.5.3 Aggregated Proof Interface

```solidity
interface IProofAggregator {

    struct StepProof {
        bytes32 pipelineId;
        uint256 stepIndex;
        bytes32 agentId;
        bytes32 codebaseHash;
        bytes32 inputHash;
        bytes32 outputHash;
        bytes32[] tlsCommitments;
        bytes foldedInstance;
        uint256 index;
    }

    struct AggregatedProof {
        bytes32 pipelineId;
        uint256 stepCount;
        bytes compressedProof;
        bytes publicInputs;
        bytes32 verificationKeyId;
    }

    event StepFolded(
        bytes32 indexed pipelineId,
        uint256 stepIndex,
        bytes32 agentId,
        bytes32 outputHash
    );

    event ProofAggregated(
        bytes32 indexed pipelineId,
        uint256 stepCount,
        bytes32 proofHash
    );

    function foldStep(
        StepProof calldata proof
    ) external returns (bytes memory foldedInstance);

    function compressProof(
        bytes32 pipelineId
    ) external returns (AggregatedProof memory);

    function verifyAggregated(
        AggregatedProof calldata proof
    ) external view returns (bool valid);

    function getVerifier(
        bytes32 verificationKeyId
    ) external view returns (address verifierContract);
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

    event VerifierDeployed(
        bytes32 indexed verificationKeyId,
        string circuitVersion,
        address verifierContract
    );

    event VerifierDeprecated(
        bytes32 indexed verificationKeyId,
        string reason
    );

    /// @dev MUST only be callable by governance
    function registerVerifier(
        string calldata circuitVersion,
        address verifierContract,
        bytes32 verificationKeyHash
    ) external returns (bytes32 verificationKeyId);

    /// @dev MUST NOT invalidate existing verified records
    function deprecateVerifier(
        bytes32 verificationKeyId,
        string calldata reason
    ) external;

    function getActiveVerifier(
        string calldata circuitVersion
    ) external view returns (VerifierRecord memory);

    function verify(
        bytes32 verificationKeyId,
        bytes calldata proof,
        bytes calldata publicInputs
    ) external view returns (bool);
}
```

#### 3.5.5 Proof Generation Reference

Implementations SHOULD use one of the following:

| Library | Use Case |
|---|---|
| [Nova](https://github.com/microsoft/Nova) | Step accumulation (folding) |
| [HyperNova](https://eprint.iacr.org/2023/573) | Steps with varying circuit sizes |
| [Spartan](https://github.com/microsoft/Spartan) | Final compression (no trusted setup) |
| [SP1](https://github.com/succinctlabs/sp1) | General computation zkVM |

Implementations using Groth16 MUST conduct an MPC
ceremony and publish the transcript.

#### 3.5.6 Partial Pipeline Verification

```solidity
enum VerificationMode {
    StepByStep,       // Tier 1/2: no aggregation
    PartialAggregate, // Mixed tiers: segment proofs
    FullAggregate     // Tier 3: single compressed proof
}

struct PipelineVerificationResult {
    bytes32 pipelineId;
    VerificationMode mode;
    bytes[] segmentProofs;
    uint8[] stepTiers;
    uint8 minimumTier;
}
```

#### 3.5.7 Aggregation Constraints

- **C-1**: Steps MUST be folded in declared order
- **C-2**: `inputHash_i` MUST equal `outputHash_(i-1)` (enforced in circuit)
- **C-3**: `agentId_i` MUST have an active `CodeRecord` with `codebaseHash_i`
- **C-4**: `tlsCommitments` count MUST equal declared PC-1 external call count
- **C-5**: `verificationKeyId` MUST reference an active verifier
- **C-6**: `compressProof` MUST revert if any declared step is missing

---

## Rationale

### 4.1 Why Extend ERC-8126 Rather Than Define a New Registry

ERC-8126 already solves agent identity, registration
deduplication, x402 payment integration, and the
crypto-economic staking framework. Redefining these
would fragment the ecosystem.

The relationship is analogous to ERC-4626 extending
ERC-20: ERC-20 defines the token interface, ERC-4626
adds vault semantics on top without redefining token
behavior.

### 4.2 Why Tiered Trust Rather Than a Single Verification Method

A single mandatory ZK proof requirement would exclude
most agents today. Tiered trust allows incremental adoption:

- **Tier 1 today**: Any agent with a Sigstore-signed build pipeline
- **Tier 2 as ecosystem matures**: Community-reviewed codebases
- **Tier 3 as ZK tooling matures**: Cryptographic runtime guarantees

### 4.3 Why ZK Preconditions Rather Than Full Code Provability

Full provability would exclude LLM-based agents entirely.
ZK Preconditions isolate non-deterministic components
behind declared black-box boundaries (PC-2), proving
everything outside those boundaries.

The unprovable region is minimized to the genuinely
non-deterministic components. Everything else is proven.
The `IVerificationHook` interface allows upgrading to
zkML proofs for the black-box region when performance
becomes practical.

### 4.4 Why TLS Notary Rather Than Trusted Oracles

Oracle networks introduce a separate trust assumption.
TLS Notary trust assumptions:
1. Agent code integrity
2. Notary server honesty (mitigated by multi-Notary threshold)
3. TLS certificate authority honesty (existing internet trust model)

TLS Notary reuses the existing internet trust model
rather than creating a new one.

### 4.5 Why Human Review for ZK Precondition Certification

Automated static analysis cannot reliably detect all
precondition violations. PC-2 (isolated non-determinism)
requires understanding semantic intent of the code.

Staking makes reviewers economically accountable.
The optimistic model (certify first, challenge after)
is proven by Optimistic Rollups and UMA oracle.

### 4.6 Why Nova/HyperNova for Proof Aggregation

Classical recursive SNARKs require approximately
2-3M constraints per recursion step. Nova's folding
scheme costs approximately 10K constraints per step —
a ~200x reduction for a 10-step pipeline.

HyperNova handles variable circuit sizes, which is
the common case in multi-agent pipelines.

### 4.7 Why codebaseHash and dependencyHash Are Separate

Separating source and dependency hashes allows
distinguishing business logic changes from supply
chain changes, reduces reviewer burden for routine
updates, and provides clearer signal to pipeline consumers.

### 4.8 Why Optimistic Challenge Rather Than Upfront Proof

No formal verification system can automatically prove
PC-2 compliance for arbitrary agent code. The optimistic
model is practical today and provides security through
economics rather than formal proofs.

### 4.9 Why Extension Interfaces Are Defined in This Standard

Defining extension points in the base standard ensures
future extensions are composable without breaking changes.
Without them, future standards adding new verification
methods would need to fork the registry or accept
incompatibility.

---

## Security Considerations

### 5.1 Code Registration Layer

**SC-01 [CRITICAL]: Sigstore Bundle Forgery**
`registerCodeRecord` MUST verify the bundle is valid
against the public Rekor log and the certificate subject
matches the caller identity.

**SC-02 [HIGH]: codebaseHash Collision**
SHA-256 collision resistance is approximately 2^128
operations. No practical attack exists. Governance MAY
upgrade the hash algorithm via `IVerifierRegistry` if
quantum threat becomes practical.

**SC-03 [HIGH]: Dependency Substitution Without Re-registration**
PC-5 separates `codebaseHash` from `dependencyHash`.
Any change MUST trigger `updateCodeRecord`. At Tier 3,
`dependencyHash` is a circuit public input.

### 5.2 Runtime Verification Layer

**SC-04 [CRITICAL]: Proof Replay Attack**
R-6 tracks commitment nullifiers in `usedCommitments`
mapping. Stale attestations are blocked by
`MAX_ATTESTATION_AGE`.

**SC-05 [CRITICAL]: Black-Box Region Manipulation**
This standard explicitly does not claim to prove
black-box region behavior. Tier 3 verification proves
code integrity of the provable region and data integrity
of external calls. It does not prove LLM behavioral
correctness. This is a declared scope boundary, not a
vulnerability.

**SC-06 [HIGH]: inputHash / outputHash Manipulation**
At Tier 3, these are public inputs to the ZK circuit.
Falsifying them produces an invalid proof. At Tier 1/2,
consumers SHOULD treat them as self-reported.

### 5.3 TLS Notary Layer

**SC-07 [CRITICAL]: Notary Collusion**
Multi-Notary threshold (Section 3.3.7) requires
compromising ceil(2N/3) Notaries simultaneously.
Staked Notaries face full slash on detected collusion.

**SC-08 [HIGH]: TLS Certificate Authority Compromise**
Inherited from existing internet PKI. Certificate
Transparency logs provide monitoring. This standard
does not introduce this risk.

**SC-09 [MEDIUM]: Attestation Timestamp Manipulation**
The commitment nullifier set (R-6) prevents reuse
regardless of timestamp. Fresh commitments cannot
be generated for stale sessions.

### 5.4 Human Review Layer

**SC-10 [CRITICAL]: Reviewer Collusion**
Review reports are public on IPFS. Any observer can
challenge. Multi-reviewer threshold requires corrupting
ceil(2N/3) independent reviewers. Serial collusion
depletes stake via `SLASH_REVIEWER_RATE` and
`REPUTATION_DECAY`.

**SC-11 [HIGH]: Reviewer Stake Insufficient for Deterrence**
`MIN_REVIEWER_STAKE` SHOULD be calibrated to agent
transaction volumes. Governance MUST adjust as ecosystem
grows.

**SC-12 [MEDIUM]: Review Timeout Griefing**
Timeout triggers partial stake slash. Repeated
timeouts trigger reputation decay and eventual
disqualification.

### 5.5 Proof Aggregation Layer

**SC-13 [CRITICAL]: Circuit Soundness Failure**
Use reference implementations from Microsoft Research.
`IVerifierRegistry` allows governance to deprecate
buggy verifiers without invalidating historical records.

**SC-14 [HIGH]: Input-Output Chaining Bypass**
Chaining constraint is enforced inside the ZK circuit
(Section 3.5.2), not only at the contract level.

**SC-15 [MEDIUM]: Verifier Contract Substitution**
`verificationKeyHash` allows any observer to verify
the deployed contract matches the declared key.
Governance actions SHOULD be subject to a timelock.
Verifier contracts SHOULD be immutable.

### 5.6 Cross-Cutting Considerations

**SC-16 [HIGH]: Governance Attack**
Security-critical governance actions MUST require
multi-signature authorization (recommended: 5-of-9)
and timelock delay (recommended: 7 days minimum).

**SC-17 [MEDIUM]: Front-Running Registration**
`registerCodeRecord` verifies `msg.sender` is the
ERC-8126 `walletAddress` or `registrantAddress`.
An attacker observing the mempool cannot front-run.

**SC-18 [LOW]: IPFS Content Availability**
Review report CIDs MUST be pinned by submitter and
agent operator. Critical on-chain fields are stored
independently of IPFS.

### 5.7 Trust Assumption Summary

| Tier | Assumption | Type |
|---|---|---|
| T1-1 | Sigstore Fulcio CA is honest | Organizational |
| T1-2 | Rekor log is append-only | Technical |
| T1-3 | Operator correctly reports codebaseHash | Social |
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

This standard does not modify ERC-8126's existing
interfaces. Agents registered under ERC-8126 without
a `CodeRecord` operate at implicit Tier 0 (unverified).
All ERC-8126 functionality is preserved.

### 6.2 Sigstore Compatibility

Any existing Sigstore signing workflow is compatible
with Tier 1 registration without modification.
Existing Rekor entry URIs can be submitted directly
as the `sigstoreBundle` field.

### 6.3 ERC-8004 Compatibility

This standard's `IVerificationHook` is designed to
be registerable as an ERC-8004 validation hook,
allowing ERC-8004 consumers to query code integrity
results through the ERC-8004 interface.

### 6.4 ERC-8150 Compatibility

This standard and ERC-8150 are complementary:
- ERC-8150 proves what the agent was authorized to do
- This standard proves whether the correct agent ran the correct code

A `VerificationRecord` from this standard can serve
as input to ERC-8150's intent verification.

### 6.5 Future Standard Compatibility

**zkML behavioral proof standards**: Future standards
MAY implement `IVerificationHook` to add black-box
region proofs. `trustTier` values above 3 are reserved
for this purpose.

**Cross-chain agent standards**: `IPipelineContext`
MAY be extended to add cross-chain step attestations
by a future standard.

**On-chain agent standards**: Fully on-chain agents
would naturally satisfy all ZK Preconditions. A future
standard MAY define how on-chain agents register using
`contractAddress` via the extension points defined here.

---

## Test Cases

Test cases are organized by component. Implementations
MUST pass all MUST tests. SHOULD tests are recommended
but not required for compliance.

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

Preconditions: `sigstoreBundle = "not-a-valid-uri"`

Action: `registry.registerCodeRecord(A, H, H_dep, "not-a-valid-uri")`

Expected: Reverts with `InvalidSigstoreBundle`

---

**T-REG-05 [MUST]: Code Record Update Supersedes Previous**

Preconditions: Agent A has active CodeRecord with `codebaseHash = H1`

Action: `registry.updateCodeRecord(A, H2, H_dep2, bundle2)`

Expected: `CodeRecordSuperseded` emitted with `(A, H1, H2)`, old record `superseded == true`, new record `superseded == false`

---

**T-REG-06 [MUST]: Zero codebaseHash Rejected**

Action: `registry.registerCodeRecord(A, bytes32(0), H_dep, bundle)`

Expected: Reverts with `InvalidCodeHash`

---

**T-REG-07 [MUST]: Duplicate codebaseHash for Same Agent Rejected**

Preconditions: Agent A already has `codebaseHash = H`

Action: `registry.registerCodeRecord(A, H, H_dep, bundle)`

Expected: Reverts with `CodeHashAlreadyRegistered`

---

**T-REG-08 [MUST]: Tier 3 Registration Blocked Without Valid Review**

Preconditions: Agent A has NO valid `ReviewCertification` for `codebaseHash H`

Action: `registry.registerCodeRecord(A, H, H_dep, bundle)` with `trustTier = 3`

Expected: Reverts with `MissingTier3Certification`

---

### 7.2 Runtime Verification Tests

**T-VER-01 [MUST]: Successful Tier 1 Verification Submission**

Preconditions: Agent A has `codebaseHash = H, trustTier = 1`

Action: `registry.submitVerification(A, H, rekorEntryHash, bytes(0), I, O)`

Expected: Returns `verificationId`, `VerificationSubmitted` emitted, `isVerificationValid(verificationId) == true`

---

**T-VER-02 [MUST]: Mismatched claimedCodeHash Rejected**

Preconditions: Agent A has `codebaseHash = H`, submitting `H' != H`

Action: `registry.submitVerification(A, H', proof, bytes(0), I, O)`

Expected: Reverts with `CodeHashMismatch`

---

**T-VER-03 [MUST]: Superseded CodeHash Rejected**

Preconditions: `H_old` has been superseded by `H_new`

Action: `registry.submitVerification(A, H_old, proof, bytes(0), I, O)`

Expected: Reverts with `CodeHashSuperseded`

---

**T-VER-04 [MUST]: Zero inputHash Rejected**

Action: `registry.submitVerification(A, H, proof, bytes(0), bytes32(0), O)`

Expected: Reverts with `InvalidInputHash`

---

**T-VER-05 [MUST]: Zero outputHash Rejected**

Action: `registry.submitVerification(A, H, proof, bytes(0), I, bytes32(0))`

Expected: Reverts with `InvalidOutputHash`

---

**T-VER-06 [MUST]: Tier 3 Invalid ZK Proof Rejected**

Preconditions: Agent A has `trustTier = 3`, `proof` fails circuit verification

Action: `registry.submitVerification(A, H, invalidProof, tls, I, O)`

Expected: Reverts with `InvalidProof`

---

**T-VER-07 [MUST]: Verification Record Retrievable**

Action: `getVerification(V)`

Expected: Returns correct `agentId, claimedCodeHash, inputHash, outputHash, trustTier, timestamp`

---

**T-VER-08 [MUST]: isVerificationValid Returns False After Challenge**

Preconditions: `V` has been successfully challenged and slashed

Action: `isVerificationValid(V)`

Expected: Returns `false`

---

### 7.3 TLS Notary Binding Tests

**T-TLS-01 [MUST]: Unregistered Notary Rejected**

Preconditions: `notaryAddress = N` not in `INotaryRegistry`

Action: `submitVerification` with attestation containing `N`

Expected: Reverts with `InvalidNotary`

---

**T-TLS-02 [MUST]: Expired Attestation Rejected**

Preconditions: `attestation.timestamp > MAX_ATTESTATION_AGE` from current block

Action: `submitVerification` with expired attestation

Expected: Reverts with `AttestationExpired`

---

**T-TLS-03 [MUST]: Replayed transcriptCommitment Rejected**

Preconditions: Commitment `C` used in previous `VerificationRecord`

Action: `submitVerification` with reused `C`

Expected: Reverts with `CommitmentAlreadyUsed`, `usedCommitments[C] == true`

---

**T-TLS-04 [MUST]: Undeclared Interface Rejected**

Preconditions: PC-1 manifest declares `["price-oracle"]`, attestation has `interfaceId = "undeclared-service"`

Action: `submitVerification` with undeclared interface attestation

Expected: Reverts with `UndeclaredInterface`

---

**T-TLS-05 [MUST]: Missing Attestation for Declared Interface Rejected**

Preconditions: PC-1 declares 2 interfaces, bundle has only 1 attestation

Action: `submitVerification` with incomplete bundle

Expected: Reverts with `MissingAttestation`

---

**T-TLS-06 [MUST]: Invalid Notary Signature Rejected**

Preconditions: `notarySignature` does not verify against `notaryAddress`

Action: `submitVerification` with bad signature

Expected: Reverts with `InvalidNotarySignature`

---

**T-TLS-07 [MUST]: Notary Registration Below Minimum Stake Rejected**

Action: `notaryRegistry.registerNotary{value: MIN_NOTARY_STAKE - 1}("https://...")`

Expected: Reverts with `InsufficientStake`

---

**T-TLS-08 [MUST]: Successful Notary Challenge and Slash**

Preconditions: Notary `N` produced provably false attestation `V`

Action: `notaryRegistry.challengeNotary(V, validEvidence)`

Expected: `NotarySlashed` emitted, `N.stake` reduced, `isValidNotary(N) == false` if below minimum

---

**T-TLS-09 [SHOULD]: Multi-Notary Threshold Enforcement**

Preconditions: Agent declares `{threshold: 2, minimum_notaries: 3}`, bundle has 1 Notary signature

Action: `submitVerification` with single-Notary bundle

Expected: Reverts with `InsufficientNotaryThreshold`

---

### 7.4 Human Review Layer Tests

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

Preconditions: Reviewer `R` has `stake < MIN_REVIEWER_STAKE`

Action: `reviewRequest.acceptReview(requestId)` called by `R`

Expected: Reverts with `ReviewerIneligible`

---

**T-REV-04 [MUST]: Successful Certification Submission**

Preconditions: Request `X` in Assigned status, `msg.sender == assignedReviewer`, valid EIP-712 signature

Action: `reviewRequest.submitCertification(X, 0b00011111, "ipfs://...", signature)`

Expected: `ReviewCertified` emitted, status `== Submitted`, `challengeDeadline == block.number + CHALLENGE_PERIOD`

---

**T-REV-05 [MUST]: Non-Assigned Reviewer Cannot Submit**

Preconditions: `msg.sender != assignedReviewer`

Action: `submitCertification(X, ...)`

Expected: Reverts with `UnauthorizedReviewer`

---

**T-REV-06 [MUST]: Challenge Within Period Accepted**

Preconditions: Status `== Submitted`, `block.number < challengeDeadline`, `msg.value >= CHALLENGE_STAKE`

Action: `challengeCertification{value: CHALLENGE_STAKE}(X, 2, "ipfs://...")`

Expected: `ReviewChallenged` emitted, status `== Challenged`, `ArbitrationOpened` emitted

---

**T-REV-07 [MUST]: Challenge After Period Rejected**

Preconditions: `block.number > challengeDeadline`

Action: `challengeCertification{value: CHALLENGE_STAKE}(X, 2, evidenceCID)`

Expected: Reverts with `ChallengePeriodExpired`

---

**T-REV-08 [MUST]: Finalize After Challenge Period**

Preconditions: Status `== Submitted`, `block.number > challengeDeadline`, no challenge submitted

Action: `reviewRequest.finalizeReview(X)`

Expected: Status `== Valid`, `reviewFee` transferred to reviewer, `isTier3Eligible(A, H) == true`

---

**T-REV-09 [MUST]: Reviewer Slash on Successful Challenge**

Preconditions: Arbitration resolved with `ChallengeSucceeds`, reviewer has `stake = S`

Expected: `S` reduced by `S * SLASH_REVIEWER_RATE`, `reputationScore` reduced by `REPUTATION_DECAY`, status `== Invalidated`

---

**T-REV-10 [MUST]: Challenger Slash on Failed Challenge**

Preconditions: Arbitration resolved with `ChallengeFails`, challenger posted `CHALLENGE_STAKE = CS`

Expected: Challenger loses `CS * SLASH_CHALLENGER_RATE`, reviewer receives `CS * REWARD_REVIEWER_RATE`, review proceeds to finalization

---

**T-REV-11 [MUST]: Review Timeout Triggers Partial Slash**

Preconditions: `block.number > assignedAt + REVIEW_TIMEOUT`

Action: `reviewRequest.enforceTimeout(X)`

Expected: Reviewer loses partial stake, status `== Pending`, `assignedReviewer` reset to `address(0)`

---

**T-REV-12 [SHOULD]: Multi-Reviewer Threshold Requires N Certifications**

Preconditions: Request requires `requiredReviewers = 3`, only 2 certifications submitted

Action: `reviewRequest.finalizeReview(X)`

Expected: Reverts with `InsufficientReviewers`

---

### 7.5 Proof Aggregation Tests

**T-AGG-01 [MUST]: Successful Single Step Fold**

Action: `aggregator.foldStep(StepProof{P, 0, A, H, I, O, [...], bytes(0), 0})`

Expected: Returns `foldedInstance != bytes(0)`, `StepFolded` emitted

---

**T-AGG-02 [MUST]: Input-Output Chaining Enforced**

Preconditions: Step 0 `outputHash = O_0`, step 1 `inputHash = I_1` where `I_1 != O_0`

Action: `aggregator.foldStep(step 1 with mismatched inputHash)`

Expected: Reverts with `InputOutputMismatch`

---

**T-AGG-03 [MUST]: Out-of-Order Step Rejected**

Preconditions: Step 0 folded, attempting step 2 before step 1

Action: `aggregator.foldStep(StepProof{stepIndex: 2, ...})`

Expected: Reverts with `StepOutOfOrder`

---

**T-AGG-04 [MUST]: Successful Pipeline Compression**

Preconditions: All N steps folded with valid instances

Action: `aggregator.compressProof(P)`

Expected: Returns `AggregatedProof` with `compressedProof != bytes(0)`, `verifyAggregated(proof) == true`

---

**T-AGG-05 [MUST]: Compression Rejected with Missing Steps**

Preconditions: Pipeline declared with 3 agents, only 2 steps folded

Action: `aggregator.compressProof(P)`

Expected: Reverts with `IncompletePipeline`

---

**T-AGG-06 [MUST]: Deprecated Verifier Rejects New Proofs**

Preconditions: `verificationKeyId V` deprecated

Action: `verifierRegistry.verify(V, proof, publicInputs)`

Expected: Reverts with `VerifierDeprecated`

---

**T-AGG-07 [MUST]: Existing Records Valid After Verifier Deprecation**

Preconditions: `VerificationRecord VR` created with deprecated verifier `V`

Action: `isVerificationValid(VR)`

Expected: Returns `true` — historical records not invalidated

---

**T-AGG-08 [MUST]: Wrong Agent in Pipeline Step Rejected**

Preconditions: Pipeline `P` declared with `[A, B]`, step 1 proof has `agentId = C`

Action: `aggregator.foldStep(StepProof{stepIndex: 1, agentId: C})`

Expected: Reverts with `AgentIdMismatch`

---

**T-AGG-09 [MUST]: TLS Commitment Count Must Match PC-1 Declaration**

Preconditions: Agent A declares 2 external interfaces, `StepProof.tlsCommitments` has 1 entry

Action: `aggregator.foldStep(...)`

Expected: Reverts with `TLSCommitmentCountMismatch`

---

**T-AGG-10 [SHOULD]: PartialAggregate Mode Accepted with Mixed Tiers**

Preconditions: 3-step pipeline, steps 0 and 2 are Tier 3, step 1 is Tier 1

Action: `registry.finalizePipeline(P, encode([segmentProof_0, segmentProof_2]))`

Expected: Finalized, `mode == PartialAggregate`, `stepTiers = [3, 1, 3]`, `minimumTier = 1`

---

### 7.6 Pipeline Integration Tests

**T-PIPE-01 [MUST]: Pipeline Initialization**

Preconditions: Agents A, B, C all have valid CodeRecords

Action: `registry.initPipeline([A, B, C])`

Expected: Returns `pipelineId`, `agentIds == [A, B, C]`, `finalized == false`

---

**T-PIPE-02 [MUST]: Step Attachment AgentId Mismatch Rejected**

Preconditions: Pipeline `P` declared with `[A, B]`, `verificationId V` belongs to agent C

Action: `registry.attachPipelineStep(P, 1, V)`

Expected: Reverts with `PipelineAgentMismatch`

---

**T-PIPE-03 [MUST]: Invalid Verification Blocks Pipeline**

Preconditions: All steps attached, step 1 verification is slashed

Action: `registry.finalizePipeline(P, proof)`

Expected: Reverts with `InvalidPipelineStep`

---

**T-PIPE-04 [MUST]: Finalized Pipeline Cannot Be Modified**

Preconditions: Pipeline P is finalized

Action: `registry.attachPipelineStep(P, 0, V)`

Expected: Reverts with `PipelineAlreadyFinalized`

---

**T-PIPE-05 [MUST]: Full Tier 3 Pipeline End-to-End**

Preconditions: Three Tier 3 agents A, B, C with valid CodeRecords and certifications

Action sequence:
1. `initPipeline([A, B, C])` → pipelineId P
2. `submitVerification(A, ...)` → V_A (outputHash O_A)
3. `submitVerification(B, inputHash=O_A, ...)` → V_B (outputHash O_B)
4. `submitVerification(C, inputHash=O_B, ...)` → V_C
5. `attachPipelineStep(P, 0, V_A)`
6. `attachPipelineStep(P, 1, V_B)`
7. `attachPipelineStep(P, 2, V_C)`
8. `foldStep(step 0)`, `foldStep(step 1)`, `foldStep(step 2)`
9. `compressProof(P)`
10. `finalizePipeline(P, proof)`

Expected: Each step succeeds, `PipelineFinalized` emitted, `finalized == true`, `verifyAggregated(proof) == true`, `mode == FullAggregate`, `minimumTier == 3`

---

### 7.7 Extension Hook Tests

**T-HOOK-01 [MUST]: Non-Governance Cannot Register Hook**

Preconditions: `msg.sender` is not governance

Action: `registry.registerVerificationHook(4, someContract)`

Expected: Reverts with `Unauthorized`

---

**T-HOOK-02 [MUST]: Hook Registered by Governance Callable**

Preconditions: Governance registers hook H for `trustTier = 4`, agent A has `trustTier = 4`

Action: `registry.submitVerification(A, ...)`

Expected: `IVerificationHook(H).verify()` called; succeeds if returns `(true, score)`, reverts if returns `(false, score)`

---

**T-HOOK-03 [MUST]: Invalid Hook Address Rejected**

Preconditions: `hookAddress` is an EOA

Action: `registry.registerVerificationHook(4, eoaAddress)`

Expected: Reverts with `InvalidHookAddress`

---

**T-HOOK-04 [SHOULD]: Pipeline Hook Called on Step Completion**

Preconditions: `IPipelineContext` hook H registered, Pipeline P has hook attached

Action: `aggregator.foldStep(StepProof)`

Expected: `IPipelineContext(H).onStepComplete()` called with correct parameters

---

### 7.8 Error Code Coverage Matrix

| Error Code | Covered By |
|---|---|
| `InvalidAddress` | T-REG-02 |
| `InvalidCodeHash` | T-REG-06 |
| `AgentNotFound` | T-REG-03 |
| `UnauthorizedAccess` | T-REG-02, T-REV-05 |
| `CodeHashAlreadyRegistered` | T-REG-07 |
| `CodeHashMismatch` | T-VER-02 |
| `CodeHashSuperseded` | T-VER-03 |
| `InvalidProof` | T-VER-06 |
| `InvalidInputHash` | T-VER-04 |
| `InvalidOutputHash` | T-VER-05 |
| `InvalidNotary` | T-TLS-01 |
| `AttestationExpired` | T-TLS-02 |
| `CommitmentAlreadyUsed` | T-TLS-03 |
| `UndeclaredInterface` | T-TLS-04 |
| `MissingAttestation` | T-TLS-05 |
| `InvalidNotarySignature` | T-TLS-06 |
| `InsufficientStake` | T-TLS-07 |
| `InvalidSigstoreBundle` | T-REG-04 |
| `MissingTier3Certification` | T-REG-08 |
| `InsufficientFee` | T-REV-02 |
| `ReviewerIneligible` | T-REV-03 |
| `UnauthorizedReviewer` | T-REV-05 |
| `ChallengePeriodExpired` | T-REV-07 |
| `InsufficientReviewers` | T-REV-12 |
| `InputOutputMismatch` | T-AGG-02 |
| `StepOutOfOrder` | T-AGG-03 |
| `IncompletePipeline` | T-AGG-05 |
| `VerifierDeprecated` | T-AGG-06 |
| `AgentIdMismatch` | T-AGG-08, T-PIPE-02 |
| `TLSCommitmentCountMismatch` | T-AGG-09 |
| `InvalidPipelineStep` | T-PIPE-03 |
| `PipelineAlreadyFinalized` | T-PIPE-04 |
| `PipelineAgentMismatch` | T-PIPE-02 |
| `Unauthorized` | T-HOOK-01 |
| `InvalidHookAddress` | T-HOOK-03 |
| `InsufficientNotaryThreshold` | T-TLS-09 |

---

## Reference Implementation

A reference implementation will be provided demonstrating:

1. `IAgentCodeRegistry` deployment on Base Sepolia testnet
2. Tier 1 registration flow (Sigstore bundle + codebaseHash)
3. Tier 2 review flow (request → assign → certify → challenge → finalize)
4. Tier 3 verification flow (ZK Precondition manifest → TLS Notary → Nova fold → Spartan compress → on-chain verify)
5. Three-agent mixed-tier pipeline in `PartialAggregate` mode

Reference implementation: `github.com/[author]/zkagent-protocol`

Circuit implementation: Built on [Nova](https://github.com/microsoft/Nova) and [Spartan](https://github.com/microsoft/Spartan)

TLS Notary integration: Built on [tlsn](https://github.com/tlsnotary/tlsn)

---

## Copyright

Copyright and related rights waived via [CC0](https://eips.ethereum.org/LICENSE).
