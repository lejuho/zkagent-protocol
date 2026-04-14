# zkagent-protocol

Runtime code integrity verification standard
for AI agents in multi-agent pipelines.

---

## The Problem

When Agent A calls Agent B across organizational
boundaries, there is no standard way to verify
that Agent B is running the code it claims to run.

Sigstore proves what was **built**.
ERC-8126 proves an agent **exists**.
This standard proves what is **running right now**.

This gap is inconsequential when an operator
controls both the registered identity and the
execution environment. It becomes critical when:

- Agents call third-party agents across trust boundaries
- An agent marketplace intermediates between providers and consumers
- A multi-step pipeline depends on sequential agent outputs
- Regulatory requirements mandate an auditable record of which code version produced a given output

---

## The Approach

Three trust tiers, each adoptable today:

| Tier | Mechanism | Infrastructure Required |
|---|---|---|
| 1 | Sigstore-signed codebase hash | None beyond existing CI |
| 2 | Crowd-sourced human review + staking | Staked reviewer network |
| 3 | ZK proof of runtime execution + TLS Notary | Nova/HyperNova + Notary server |

Tier 1 is available to any agent with a standard
Sigstore build pipeline. Tier 3 provides
cryptographic runtime guarantees with no trusted
hardware requirement.

---

## Key Design Decisions

**Extends ERC-8126, not a new registry**
Agent identity, staking infrastructure, and x402
payment integration are reused from ERC-8126.
This standard adds a code integrity layer on top.

**ZK Preconditions, not full determinism**
LLM-based agents are non-deterministic by design.
Five structural preconditions (PC-1 through PC-5)
define a ZK-compatible code structure that isolates
non-deterministic components behind declared
black-box boundaries. Everything outside those
boundaries is proven.

**TLS Notary over oracle networks**
External data authenticity is proven using the
TLS session transcript directly, without requiring
a separate oracle validator network.

**Nova/HyperNova for pipeline aggregation**
Individual step proofs are folded using Nova's
IVC scheme (~10K constraints per step) and
compressed with Spartan at the end. A 10-agent
pipeline produces a single constant-size proof
regardless of depth.

**Optimistic human review**
ZK Precondition compliance is certified by staked
reviewers. Anyone can challenge within the
challenge period. Economic stake deters false
certifications.

---

## Standard Document

Full ERC draft: [erc-agent-code-integrity.md](./erc-agent-code-integrity.md)

Sections:
- Abstract
- Motivation
- Specification
  - 3.1 Interface Definitions
  - 3.2 ZK Preconditions
  - 3.3 TLS Notary Binding
  - 3.4 Human Review Layer
  - 3.5 Recursive Proof Aggregation
- Rationale
- Security Considerations
- Backwards Compatibility
- Test Cases (46 cases across 7 components)

---

## Relationship to Other Standards

| Standard | Relationship |
|---|---|
| ERC-8126 | Extended by this standard (requires) |
| ERC-8004 | `IVerificationHook` registerable as ERC-8004 validation hook |
| ERC-8150 | Complementary — 8150 proves intent, this proves execution |
| Sigstore | Tier 1 trust anchor, reused without modification |
| TLSNotary | External data integrity layer (github.com/tlsnotary/tlsn) |
| Nova | Step proof accumulation (github.com/microsoft/Nova) |
| Spartan | Final proof compression (github.com/microsoft/Spartan) |

---

## Status

```
Document:             Complete draft
Ethereum Magicians:   Pending (link TBD)
ethereum/ERCs PR:     Pending
Reference impl:       Planned (Base Sepolia)
```

---

## License

CC0 — copyright and related rights waived.
