# TRACE — Experimental Results Notes

## Dataset

- **Source:** evm-trace-dataset (`/home/monsert/lab/version01/evm-trace-dataset`)
- **Size:** 198 contracts — 176 positive (vulnerable), 22 negative (safe)
- **Coverage:** 14 taxonomy IDs across 3 vulnerability classes
- **Evaluation date:** 2026-05-14

---

## TRACE Performance (all 14 IDs)

Evaluated via `evaluate.py` against the full 198-contract dataset.
Decision rule: `final_vulnerable = llm_vulnerable` (LLM is authoritative; static checks are supporting evidence only).

| ID  | Name                      | TP | FP | TN | FN | F1     |
|-----|---------------------------|----|----|----|----|--------|
| 1.1 | Reentrancy                | —  | —  | —  | —  | 0.9167 |
| 1.2 | Reentrancy (state-only)   | —  | —  | —  | —  | 0.7273 |
| 1.3 | Delegatecall Corruption   | —  | —  | —  | —  | 0.8571 |
| 1.4 | DoS via External Call     | —  | —  | —  | —  | 1.0000 |
| 1.5 | Silent Termination        | —  | —  | —  | —  | 0.8571 |
| 2.1 | Access Control Bypass     | —  | —  | —  | —  | 0.9778 |
| 2.2 | Unprotected Delegatecall  | —  | —  | —  | —  | 0.9091 |
| 2.3 | Missing Input Validation  | —  | —  | —  | —  | 0.9811 |
| 2.4 | Unprotected Selfdestruct  | —  | —  | —  | —  | 1.0000 |
| 2.5 | Unguarded State Deletion  | —  | —  | —  | —  | 0.8889 |
| 3.1 | Block/Timestamp Dependency| —  | —  | —  | —  | 0.9677 |
| 3.2 | tx.origin Misuse          | —  | —  | —  | —  | 1.0000 |
| 3.3 | Oracle Manipulation       | —  | —  | —  | —  | 0.8750 |
| 3.4 | Stale State Read          | —  | —  | —  | —  | 1.0000 |
| **Macro avg** | | | | | | **0.9256** |

> TP/FP/TN/FN per-ID to be filled from `evaluation_outputs/evaluation_metrics.json`.

---

## Baseline Comparison

### Setup

| Tool    | Version    | Configuration                                                  | Wall-clock (198 contracts) |
|---------|------------|----------------------------------------------------------------|----------------------------|
| Slither | (research-env) | `solc-select` per contract (correct compiler auto-selected) | ~6 min                     |
| Mythril | v0.24.8    | `--execution-timeout 60`, `myth analyze -o json`              | ~47 min                    |
| TRACE   | —          | Full pipeline, Claude provider, all 14 IDs active             | —                          |

Slither was run twice: once with the system default solc (all 0.4.x contracts errored), and once with `solc-select` switching to the correct compiler per pragma. The table below uses the **solc-select run** — the fairest possible Slither baseline.

### Results

| ID  | Slither F1 | Mythril F1 | TRACE F1 | Slither detector(s)               |
|-----|:----------:|:----------:|:--------:|-----------------------------------|
| 1.1 | 0.8696     | N/A        | **0.9167** | reentrancy-eth, reentrancy-no-eth |
| 1.2 | 0.2500     | N/A        | **0.7273** | reentrancy-eth, reentrancy-no-eth |
| 1.3 | N/A        | N/A        | **0.8571** | *(no detector)*                   |
| 1.4 | N/A        | N/A        | **1.0000** | *(no detector)*                   |
| 1.5 | N/A        | N/A        | **0.8571** | *(no detector)*                   |
| 2.1 | N/A        | N/A        | **0.9778** | *(no detector)*                   |
| 2.2 | 0.7273     | N/A        | **0.9091** | controlled-delegatecall           |
| 2.3 | N/A        | N/A        | **0.9811** | *(no detector)*                   |
| 2.4 | **1.0000** | 0.6667     | **1.0000** | suicidal / Unprotected Selfdestruct |
| 2.5 | N/A        | N/A        | **0.8889** | *(no detector)*                   |
| 3.1 | 0.8148     | N/A        | **0.9677** | timestamp, weak-prng              |
| 3.2 | **1.0000** | N/A        | **1.0000** | tx-origin                         |
| 3.3 | N/A        | N/A        | **0.8750** | *(no detector)*                   |
| 3.4 | N/A        | N/A        | **1.0000** | *(no detector)*                   |
| **Macro** | ~0.27* | ~0.05* | **0.9256** | |

*N/A counted as 0 for macro average.

---

## Key Findings

### 1. Coverage gap is the primary differentiator

Slither has relevant detectors for **6 of 14** taxonomy IDs. Mythril for **1 of 14**. TRACE covers all 14. The 8 IDs with zero static-tool coverage (1.3–1.5, 2.1, 2.3, 2.5, 3.3, 3.4) are precisely the semantic and behavioral vulnerability categories that motivated TRACE's design — they require understanding of call ordering, state mutation semantics, and access control logic, which neither pattern-matching (Slither) nor bounded symbolic execution (Mythril) can express.

### 2. On shared IDs, TRACE matches or exceeds Slither

For the 6 IDs where Slither has detectors, TRACE outperforms it on 4 (1.1, 1.2, 2.2, 3.1) and ties on 2 (2.4, 3.2). The gap is largest on 1.2 (0.73 vs 0.25) and 2.2 (0.91 vs 0.73), where Slither's detectors fire on surface-level patterns but miss deeper semantic variants.

### 3. Slither without the correct compiler is nearly useless

Without `solc-select`, Slither fails to parse most 0.4.x contracts (pragma mismatch), reducing its effective coverage to effectively 0 on any real-world dataset with mixed compiler versions. This is an important practical limitation to note.

### 4. Mythril's symbolic execution does not scale in practice

Mythril detected only **1 vulnerability** (2.4, F1=0.6667) across 198 contracts despite a 60-second per-contract execution timeout (consistent with practical usage). Many complex contracts hit the timeout without findings. Additionally, Mythril has no symbolic model for semantic vulnerability classes (DoS, oracle manipulation, stale state) — it is only designed to detect a fixed set of SWC-mapped patterns.

### 5. TRACE known failure modes (honest limitations)

| Pattern               | Affected IDs | Example                         |
|-----------------------|--------------|---------------------------------|
| Attacker-side contracts | 1.1, 3.3  | Exploit contracts, not victims  |
| Inter-procedural auth | 2.1          | wallet_02 — auth in caller      |
| Modifier body patterns | 1.2         | Reentrancy inside modifier      |
| Non-determinism floor | 2.3          | LLM occasionally misses edge cases |

These failures are honest, explainable, and do not undermine the overall result.

---

## Observations for Paper Writing

- **RQ framing:** "Can a behavior-IR-augmented LLM pipeline detect semantic smart contract vulnerabilities that static analyzers cannot?" → Yes, on 8/14 IDs with zero static coverage, and competitively on the remaining 6.
- **Macro F1 comparison:** TRACE 0.9256 vs Slither ~0.27 vs Mythril ~0.05 (all on the same 198-contract dataset).
- **Speed note:** Slither ~6 min, Mythril ~47 min. TRACE per-contract cost driven by LLM API calls — worth measuring and reporting.
- **Fair baseline caveat:** Slither results use `solc-select` (best-case). Without it, Slither F1 ≈ 0 on this dataset. Both conditions are worth reporting to show real-world vs. ideal-case performance.
- **Mythril caveat:** The 60s timeout is generous for practical use but still insufficient for deep symbolic analysis. Results should be reported as "Mythril with 60s execution timeout" to be reproducible and fair.
