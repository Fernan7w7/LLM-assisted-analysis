# TRACE — Trace-Based Reasoning for Automated Contract Examination

A research pipeline that uses **Large Language Models** augmented with a lightweight behavioral IR to detect semantic and logic-level vulnerabilities in Ethereum smart contracts — across all 14 vulnerability IDs of the TRACE taxonomy.

---

## Research Question

> Can a behavior-IR-augmented LLM pipeline detect Solidity vulnerabilities across the full spectrum of vulnerability classes — from operation-ordering violations to state-visibility exploits — without requiring compilation or full project context?

Our evaluation answers: **yes**, with macro-averaged F1 = **0.9256** across 14 vulnerability IDs on 198 labeled contracts.

---

## Key Results

| ID  | Name                      | TP  | FP | TN | FN  | Precision | Recall | F1     |
|-----|---------------------------|-----|----|----|-----|-----------|--------|--------|
| 1.1 | Reentrancy                | 33  | 0  | 0  | 6   | 1.000     | 0.846  | 0.9167 |
| 1.2 | Reentrancy (State-Only)   | 4   | 0  | 0  | 3   | 1.000     | 0.571  | 0.7273 |
| 1.3 | Delegatecall Corruption   | 3   | 1  | 2  | 0   | 0.750     | 1.000  | 0.8571 |
| 1.4 | DoS via External Call     | 6   | 0  | 2  | 0   | 1.000     | 1.000  | 1.0000 |
| 1.5 | Silent Termination        | 3   | 0  | 4  | 1   | 1.000     | 0.750  | 0.8571 |
| 2.1 | Access Control Bypass     | 22  | 0  | 1  | 1   | 1.000     | 0.957  | 0.9778 |
| 2.2 | Unprotected Delegatecall  | 5   | 1  | 1  | 0   | 0.833     | 1.000  | 0.9091 |
| 2.3 | Missing Input Validation  | 52  | 0  | 1  | 2   | 1.000     | 0.963  | 0.9811 |
| 2.4 | Unprotected Selfdestruct  | 2   | 0  | 1  | 0   | 1.000     | 1.000  | 1.0000 |
| 2.5 | Unguarded State Deletion  | 4   | 1  | 3  | 0   | 0.800     | 1.000  | 0.8889 |
| 3.1 | Block/Timestamp Dep.      | 15  | 0  | 0  | 1   | 1.000     | 0.938  | 0.9677 |
| 3.2 | tx.origin Misuse          | 2   | 0  | 0  | 0   | 1.000     | 1.000  | 1.0000 |
| 3.3 | Price Oracle Manipulation | 7   | 0  | 2  | 2   | 1.000     | 0.778  | 0.8750 |
| 3.4 | Stale State Read          | 2   | 0  | 2  | 0   | 1.000     | 1.000  | 1.0000 |
| **Macro avg** | | | | | | **0.978** | **0.900** | **0.9256** |

**Model:** GPT-4o | **Dataset:** 198 contracts (176 positive, 22 negative) | **Provider:** `PROVIDER=gpt`

---

## Vulnerability Taxonomy

The TRACE taxonomy organizes 14 vulnerability IDs into 3 classes based on the type of trace-level property they violate.

### Class 1 — Operation Ordering Violations
Vulnerabilities caused by executing operations in the wrong order relative to external calls or state transitions.

| ID  | Name | Description |
|-----|------|-------------|
| 1.1 | Reentrancy | External call before state update (CEI violation) |
| 1.2 | Reentrancy (State-Only) | Callback-based reentrancy via ERC-777 / flash loan hooks |
| 1.3 | Delegatecall State Corruption | Delegatecall overwrites proxy storage slots; slot collision or uninitialized proxy |
| 1.4 | DoS via External Call | Reverting callee blocks shared settlement path for all participants |
| 1.5 | Silent Termination | Selfdestruct fires without a preceding event emit |

### Class 2 — Guard Absence Violations
Vulnerabilities caused by missing authorization, validation, or return-value checks.

| ID  | Name | Description |
|-----|------|-------------|
| 2.1 | Access Control Bypass | Privileged function reachable by unauthorized caller |
| 2.2 | Unprotected Delegatecall | Delegatecall target is caller-supplied with no auth check |
| 2.3 | Missing Input Validation | Missing zero-address, amount, phase, re-init, or return-value check |
| 2.4 | Unprotected Selfdestruct | Selfdestruct callable by any external account |
| 2.5 | Unguarded State Deletion | Critical storage deleted without caller authorization |

### Class 3 — State Visibility Violations
Vulnerabilities caused by reading stale, manipulable, or unreliable state.

| ID  | Name | Description |
|-----|------|-------------|
| 3.1 | Block/Timestamp Dependency | block.timestamp / block.number used for randomness or sole timing gate |
| 3.2 | tx.origin Misuse | Authorization via tx.origin instead of msg.sender |
| 3.3 | Price Oracle Manipulation | Spot AMM price or stale Chainlink feed used without TWAP / staleness check |
| 3.4 | Stale State Read | State variable cached before external call; stale value used post-call |

---

## Architecture

```
Solidity Contract (.sol)
       ↓
Function Extraction          [parsing/solidity_parser.py]
   Regex + brace matching; extracts named functions, fallbacks, receive
       ↓
Behavior Extraction — IR     [parsing/behavior_extractor.py]
   Per-function signals:
   ├─ Operation sequence: WRITE / CALL / DELEGATECALL / SELFDESTRUCT / EMIT / CHECK
   ├─ CEI-order: writes_before_call, writes_after_call, cei_safe_order
   ├─ has_auth_check, has_require, has_zero_address_check, has_amount_check
   ├─ has_external_call, has_delegatecall, has_selfdestruct, has_delete
   ├─ has_tx_origin, has_block_dependency, emit_before_selfdestruct
   └─ has_oracle_read, delegatecall_uses_variable_target
       ↓
Candidate Filtering          [pipeline/runner.py]
   Per-ID IR-first filters; generic keyword fallback
       ↓
LLM Two-Stage Reasoning      [prompts/templates.py + analyzers/]
   Stage 1 — Scenario: does this function match the vulnerability pattern?
   Stage 2 — Property: is the risky condition actually present?
   Both stages must agree; LLM decision is final (final_vulnerable = llm_vulnerable)
       ↓
Triage                       [pipeline/triage.py]
   Class-based priority (Class 1 > Class 2 > Class 3); primary / secondary labels
       ↓
Report                       [pipeline/reporting.py]
   Console + JSON output
```

---

## Dataset

| Source | Contracts | Notes |
|--------|-----------|-------|
| SmartBugs | ~60 | Classic SWC-registry contracts |
| DeFiHack | ~50 | Real DeFi exploit reproductions (Foundry) |
| NSSC | ~30 | Not-so-smart-contracts benchmark |
| Synthetic (paired) | 44 | 22 positive/negative pairs, one per vulnerability pattern |
| **Total** | **198** | 176 positive, 22 negative |

Dataset location: `../evm-trace-dataset` (cloned separately)

---

## Known Limitations

All remaining false negatives fall into three structural root causes:

| Root Cause | Affected IDs | Examples |
|---|---|---|
| **Attacker-side contracts** | 1.1, 1.2, 3.3 | Exploit contracts show attacker flow; victim is in a separate contract |
| **Inter-procedural scope** | 1.2, 1.5, 2.1, 2.5 | Vulnerability spans modifier bodies or caller/callee chains beyond single-function view |
| **Library/special constructs** | 3.1 | `library` functions skipped; `now` alias added for 0.4.x |

False positives (3 total) reflect semantic gaps: cross-contract storage layout analysis (1.3), owner-controlled mapping target reasoning (2.2), and internal function caller-context tracing (2.5).

---

## Project Structure

```
pipeline/
  runner.py               — core analysis loop; per-ID filter dispatch
  triage.py               — class-based priority resolution
  reporting.py            — console and JSON output

parsing/
  solidity_parser.py      — function extraction (regex + brace matching)
  behavior_extractor.py   — lightweight IR extraction (14 signals)

prompts/
  templates.py            — per-ID scenario and property prompt templates

analyzers/
  gpt.py                  — OpenAI GPT provider
  claude.py               — Anthropic Claude provider
  gemini.py               — Google Gemini provider

data/
  taxonomy.py             — 14-ID taxonomy, ACTIVE_IDS, VULNERABILITY_SCENARIOS

evaluate.py               — evaluation runner; loads evm-trace-dataset labels
```

---

## Installation

```bash
python -m venv ../research-env
source ../research-env/bin/activate
pip install -r requirements.txt
```

---

## Environment Variables

```env
OPENAI_API_KEY=your_key_here
CLAUDE_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
```

---

## Usage

Analyze a single contract:
```bash
source ../research-env/bin/activate
PROVIDER=gpt python3 -m pipeline.runner path/to/contract.sol
```

Run evaluation for a specific ID:
```bash
PROVIDER=gpt python3 evaluate.py --ids 1.1
PROVIDER=gpt python3 evaluate.py --ids 2.3
```

---

## Comparison with GPTScan

This work adopts the two-stage scenario → property reasoning framework from GPTScan (ICSE 2024) and extends it in the following ways:

| Dimension | GPTScan | TRACE |
|---|---|---|
| **Core pipeline** | Two-stage: scenario → property | Two-stage: scenario → property (adopted) |
| **Preprocessing** | Full AST + CFG + DDG | Lightweight regex-based behavioral IR |
| **Compilation required** | Yes | No — works on isolated `.sol` files |
| **Static role** | Hard gate on LLM findings | Supporting evidence only — LLM is final |
| **Vulnerability categories** | 10 DeFi-specific logic bugs | 14 IDs across 3 classes (ordering, guard, visibility) |
| **Dataset scale** | ~400 projects, ~3,000 files | 198 contracts across all 14 IDs |
| **Model** | GPT-3.5-turbo (2023) | GPT-4o; supports Claude and Gemini |

**One-sentence framing:** *"TRACE extends GPTScan's two-stage reasoning approach to a broader trace-based vulnerability taxonomy, removes the compilation dependency through a lightweight behavioral IR, and covers 14 vulnerability IDs including structural, semantic, and state-visibility categories."*

---

## Disclaimer

This tool is for **research and educational purposes only**.
Do not rely on it for auditing production smart contracts.

---

## Author

Fernando Centurión
Computer Science Student | Smart Contract Security Research | NYCU
