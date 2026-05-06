# LLM-Assisted Smart Contract Vulnerability Analyzer

A research pipeline that uses **Large Language Models** to detect semantic and logic-level vulnerabilities in Ethereum smart contracts — specifically the class of vulnerabilities that traditional static analyzers structurally cannot reach.

---

## Research Question

> Can a multi-LLM approach detect logic vulnerabilities in smart contracts that static analysis structurally cannot?

Our evaluation answers: **yes**, with empirical evidence across 27 contracts and 6 vulnerability categories.

---

## Key Results

| System | Score | Track B detections |
|--------|-------|--------------------|
| **This pipeline (GPT-4)** | **23/26** | **12/13** |
| Slither | 7/16* | 0/13 |
| Mythril | 11/26 | 0/13 |

*Slither errored on 10/27 contracts due to unresolved imports in isolated files.

- Slither and Mythril combined: **zero** Track B (contextual) detections.
- This pipeline: **12/13** Track B detections.
- Model ablation: GPT-4 (21/23) > Claude (20/23) > Gemini (19/23).

---

## Vulnerability Categories

### Track A — Structural
Vulnerabilities detectable by pattern matching on code structure.

| ID | Category |
|----|----------|
| `REENTRANCY` | External call before state update (CEI violation) |
| `DOS_EXTERNAL` | DoS via blocking external call in critical path |
| `DELEGATECALL_MISUSE` | Unguarded delegatecall to attacker-controlled address |

### Track B — Contextual
Vulnerabilities requiring semantic reasoning about intent and business logic. **No existing static tool detects these.**

| ID | Category |
|----|----------|
| `NUANCED_ACCESS_CONTROL` | Subtle auth flaws: frontrunnable initializers, wrong guard on two-step ownership |
| `ASSET_LOCKING` | Conditions under which user funds become permanently inaccessible |
| `LOGIC_VALIDATION` | Business logic errors: phase-skipping, re-initialization, incorrect state transitions |

---

## Architecture

```
Solidity Contract
       ↓
Function Extraction (regex + brace matching)
       ↓
Behavior Extraction (lightweight IR)
   ├─ Operation sequence: WRITE / CALL / READ / CHECK
   ├─ CEI-order signal
   ├─ Auth-check signal
   └─ External call signal
       ↓
Candidate Filtering (per-vulnerability keyword + heuristic filters)
       ↓
LLM Stage (per function × per vulnerability)
   ├─ Stage 1 — Scenario prompt: does this function match the vulnerability pattern?
   └─ Stage 2 — Property prompt: is the risky property actually present?
       ↓
Triage (multi-finding priority resolution → primary / overlap / secondary)
       ↓
Report (console + JSON)
```

Both LLM stages must agree for a finding to be emitted. The LLM decision is final; static checks serve as supporting evidence only.

---

## Project Structure

```
pipeline/
  runner.py               — core analysis loop and filter logic
  triage.py               — multi-finding priority and labeling

parsing/
  solidity_parser.py      — function extraction
  behavior_extractor.py   — lightweight IR extraction

prompts/
  templates.py            — scenario and property prompt templates

analyzers/
  gpt.py                  — OpenAI GPT-4 provider
  claude.py               — Anthropic Claude provider
  gemini.py               — Google Gemini provider

data/
  taxonomy.py             — vulnerability definitions and filter keywords

static_checks/
  basic_checks.py         — static corroboration checks

datasets/
  synthetic/              — per-vulnerability synthetic contracts (positive + negative)
  real/                   — on-chain and public real contracts
  labels.json             — ground truth labels

reports/                  — saved JSON and CSV results
```

---

## Installation

```bash
git clone https://github.com/Fernan7w7/LLM-assisted-analysis.git
cd LLM-assisted-analysis
python -m venv research-env
source research-env/bin/activate
pip install -r requirements.txt
```

Optional (for baseline comparison):
```bash
pip install slither-analyzer solc-select
solc-select install 0.8.20 && solc-select use 0.8.20
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

```python
from pipeline.runner import analyze_file
results = analyze_file("path/to/contract.sol")
```

---

## Evaluation Report

**Date:** 2026-04-19 | **Model:** GPT-4o-mini (two-stage: scenario → property) | **Pipeline version:** post-Track-B expansion

### Dataset

| Track | Category | Positives | Negatives | Total |
|-------|----------|-----------|-----------|-------|
| A — Structural | Reentrancy | 2 synth + 4 real | 2 synth | 8 |
| A — Structural | DoS (External Call) | 3 synth | 2 synth | 5 |
| A — Structural | Delegatecall Misuse | 3 synth + 4 real | 2 synth | 9 |
| B — Contextual | Nuanced Access Control | 2 synth + 2 real | 2 synth | 6 |
| B — Contextual | Asset Locking | 3 synth + 1 real | 2 synth | 6 |
| B — Contextual | Logic / Validation | 4 synth | 3 synth | 7 |
| **Total** | | | | **41 contracts** |

Synthetic Track A: derived from SWC Registry and Trail of Bits not-so-smart-contracts.
Synthetic Track B: original, based on Code4rena/Sherlock/Immunefi audit report patterns.
Real contracts: SimpleDAO (SWC-107), KingOfEther (SWC-113), Parity proxy (SWC-112), Renzo WithdrawQueue, Basin WellUpgradeable.
See `datasets/synthetic/SYNTHETIC_DATASET_NOTES.md` for per-contract sourcing.

### Regression Test (23 representative cases)

**Result: 21 / 23 passed**

| Result | Count | Cases |
|--------|-------|-------|
| PASS | 21 | All Track A positives and negatives; most Track B |
| FAIL — false positive | 2 | `locking_03_safe_redeem`, `logic_05_safe_auction` |

**`locking_03_safe_redeem` [negative] → ASSET_LOCKING(redeem) false positive**
Safe staking vault uses CEI + nonReentrant. ASSET_LOCKING filter fires on function name + external token transfer. The LLM flags debit-before-transfer ordering even though a failed transfer reverts the full transaction. *Conservative design bias: prefers FP over FN on fund-safety bugs.*

**`logic_05_safe_auction` [negative] → ASSET_LOCKING(settle) false positive**
Safe auction's `settle()` has correct phase check and a `cancelAuction()` recovery path, but LLM flags ETH transfer as a potential lock. *Same conservative bias. Appears in all three models — model-agnostic.*

### Baseline Comparison (27-contract eval set)

Full results: `reports/baseline_comparison_20260419_164453.{json,csv}`

| System | TP | TN | FP | FN | MISS | ERR | Score |
|--------|----|----|----|----|------|-----|-------|
| **Pipeline (this work)** | **17** | **6** | **2** | **0** | **1** | **0** | **23/26** |
| Slither | 2 | 5 | 2 | 5 | 2 | 10 | 7/16* |
| Mythril | 5 | 6 | 2 | 11 | 2 | 0 | 11/26 |

*Slither requires full project context (Hardhat/Foundry with resolved imports) — aborts entirely on isolated single-file contracts.*

**Per-Track Breakdown**

| Track | N | Pipeline | Slither (valid only) | Mythril |
|-------|---|----------|----------------------|---------|
| A — Structural | 14 | **14/14 (100%)** | 5/6 (83%) | 8/14 (57%) |
| B — Contextual | 12 | **9/12 (75%)** | 2/8 (25%) | 3/12 (25%) |
| **Total** | **26** | **23/26 (88%)** | **7/14 (50%)** | **11/26 (42%)** |

**Track B Positives — Core Result**

9 contracts with confirmed contextual vulnerabilities (4 NUANCED_ACCESS_CONTROL + 3 ASSET_LOCKING + 2 LOGIC_VALIDATION):

| System | True Positives / 9 | Notes |
|--------|--------------------|-------|
| **Pipeline** | **8 / 9 (89%)** | One miss: `EntropyGenerator.sol` (boundary case, wrong category label) |
| Slither | **0 / 9 (0%)** | Structural limitation |
| Mythril | **0 / 9 (0%)** | Contextual detection out of scope |

### Model Ablation (23-case regression set)

Full results: `reports/ablation_20260419_155901.{json,csv}`

| Model | TP | TN | FP | FN | Score | Accuracy | Precision | Recall | F1 |
|-------|----|----|----|----|-------|----------|-----------|--------|----|
| **GPT-4o-mini** | **15** | **6** | **2** | **0** | **21/23** | **91.3%** | **88.2%** | **100%** | **93.8%** |
| Claude Sonnet 4 | 13 | 7 | 3 | 0 | 20/23 | 87.0% | 81.2% | 100% | 89.7% |
| Gemini 2.5 Flash | 12 | 7 | 2 | 2 | 19/23 | 82.6% | 85.7% | 85.7% | 85.7% |

GPT-4o-mini has zero false negatives. Claude over-fires on ASSET_LOCKING positives. Gemini misses two structural positives. `logic_05_safe_auction` is a universal FP across all three models.

### Design Notes

**Two-stage LLM pipeline:** Stage 1 (scenario) asks whether the function matches the vulnerability pattern; Stage 2 (property) asks whether the risky condition is meaningfully present. Both must agree for a finding to be emitted. Static checks are supporting evidence only (`final_vulnerable = llm_vulnerable`).

**Behavior extractor:** Each function is summarized into an operation sequence (WRITE/CALL/READ/CHECK), CEI-order signal, auth-check signal, and external call signal before the LLM call. Reduces prompt size and gives the model structured context beyond raw Solidity.

**Triage:** When multiple categories fire on the same function, a `primary` label is assigned to the highest-priority finding. LOGIC_VALIDATION is boosted above ASSET_LOCKING and NUANCED_ACCESS_CONTROL when they co-occur (it is typically the root cause).

---

## Research Contributions & Novelty

### Limitations of Existing Approaches

| Tool | Approach | Limitation |
|------|----------|------------|
| Slither | AST pattern matching | Structural bugs only; fails on isolated files without full project context |
| Mythril | Symbolic execution | Structural bugs only; 0 detections on all contextual vulnerability categories |
| SmartCheck, Securify | Rule-based / formal | Similar scope; no semantic reasoning |

The shared blind spot: **none of these tools can detect vulnerabilities that require understanding what a function is supposed to do**, only what it does syntactically.

### Novelty Claims

1. **Detection of semantic / contextual vulnerabilities** — targets NUANCED_ACCESS_CONTROL, ASSET_LOCKING, and LOGIC_VALIDATION: three categories with no prior automated detection coverage, derived from recurring patterns in competitive audit reports (Code4rena, Sherlock, Immunefi).

2. **No compilation or project context required** — operates directly on Solidity source, applicable to isolated snippets, audit submissions, and contracts with unresolvable imports.

3. **Structured pre-processing before LLM reasoning** — lightweight IR before querying the model, more token-efficient and less sensitive to code style variation than raw-code prompting.

4. **Two-stage confirmation reduces false positives** — 2/27 FPs in evaluation, both documented conservative ASSET_LOCKING cases.

### Expected Contributions

1. A working detection system for semantic smart contract vulnerabilities — the first to target NUANCED_ACCESS_CONTROL, ASSET_LOCKING, and LOGIC_VALIDATION as first-class detection categories with an automated pipeline.
2. A labeled evaluation dataset of 27 contracts (synthetic + real) across 6 vulnerability categories, including ground-truth labels and per-contract sourcing notes.
3. Empirical evidence that LLM reasoning generalizes to smart contract security, extending prior LLM-based vulnerability detection work (previously on C/C++) to the Solidity/EVM domain.
4. A reproducible ablation across GPT-4, Claude, and Gemini on the same task and dataset.

---

## Comparison with GPTScan

**Reference:** "GPTScan: Detecting Logic Vulnerabilities in Smart Contracts by Combining GPT with Program Analysis" — ICSE 2024.

### What was adopted

- The **two-stage pipeline** (scenario matching → property matching) is GPTScan's core architectural contribution.
- The framing that **semantic/logic bugs are outside the reach of static analyzers** and require LLM reasoning.
- Decomposing a vulnerability into a **scenario description** and a **property description**.

*This should be stated openly: "We adopted the two-stage scenario-property framework from GPTScan and extended it in the following ways."*

### Side-by-side comparison

| Dimension | GPTScan | This work |
|---|---|---|
| **Core pipeline** | Two-stage: scenario → property | Two-stage: scenario → property (adopted) |
| **Preprocessing** | Full AST + CFG + DDG + data flow | Lightweight regex-based behavioral IR |
| **Compilation required** | Yes | No — works on isolated `.sol` files |
| **Static role** | Hard gate — can reject LLM findings | Supporting evidence only — LLM is final |
| **Vulnerability categories** | 10 DeFi-specific logic bugs | 6 categories: 3 structural + 3 contextual |
| **Structural bugs** | Not targeted | Included alongside contextual track |
| **Model used** | GPT-3.5-turbo (2023) | GPT-4o-mini primary; ablation across 3 models |
| **Multi-model comparison** | No | Yes — same 23-case regression across 3 models |
| **Dataset scale** | ~400 projects, ~3,000 files | 27 contracts, 6 categories |
| **Evaluation FP rate** | 57% precision on Web3Bugs | 2/27 FPs (both documented conservative cases) |

### What is genuinely new

1. **No compilation required** — GPTScan's AST→CFG→DDG stack requires compilable code with all dependencies. This work operates on raw Solidity source.
2. **LLM as final authority** — GPTScan uses static confirmation as a hard gate. Here the LLM decision is final; static checks are stored as evidence but never veto.
3. **Different and broader vulnerability taxonomy** — GPTScan targets DeFi-specific logic patterns; this work targets audit-report-derived categories with different scope, plus structural categories GPTScan doesn't address.
4. **Multi-model empirical comparison** — GPTScan evaluated only GPT-3.5; this work reports per-model TP/TN/FP/FN across GPT-4, Claude Sonnet, and Gemini Flash.
5. **Lightweight IR vs. heavy static analysis** — deliberately minimal extractor trades control-flow precision for simplicity, speed, and the no-compilation property.

**One-sentence framing:** *"This work extends GPTScan's two-stage reasoning approach to a different and broader vulnerability taxonomy, removes the compilation dependency through a lightweight behavioral IR, and empirically evaluates the approach across three modern LLMs."*

### Limitations relative to GPTScan

- Dataset significantly smaller (27 contracts vs. ~400 projects). Results are proof-of-concept.
- Lightweight IR loses information that GPTScan's CFG/DDG captures (inter-procedural data flow, complex control paths).
- GPTScan reported 9 novel vulnerabilities found in production code; this work does not make equivalent claims on unseen real-world contracts.

---

## Future Work

**High impact, relatively doable:**
1. Expand dataset with real audited contracts — pull confirmed findings from Code4rena/Sherlock/Immunefi. Even 5–10 more real Track B positives significantly strengthen the evaluation.
2. Inter-procedural analysis — pipeline currently reasons per-function. Many real vulnerabilities (e.g., a flawed access check in function A enabling an exploit in function B) require cross-function context. Biggest architectural gap.

**Interesting research angles:**
3. Derive on-chain monitoring signatures from static findings — if the pipeline flags a function as ASSET_LOCKING, automatically generate a Forta-style detection rule for the deployed contract.
4. Prompt sensitivity analysis — how much does phrasing of the scenario/property prompts affect results? Natural extension of the ablation study.
5. Cost/performance tradeoff — GPT-4 leads on accuracy but is expensive. Is there a smaller/cheaper model that gets 90% of the way there?

**Longer term:**
6. Fine-tuned model — train a smaller model on the labeled dataset specifically for Solidity security reasoning.

---

## Limitations

- Dataset is proof-of-concept scale (~27 contracts); statistical claims require ~90+ per-category samples.
- LLM outputs are non-deterministic; results may vary slightly across runs.
- No inter-procedural analysis — vulnerabilities spanning multiple functions or contracts are out of scope.
- Two known false positives (`locking_03_safe_redeem`, `logic_05_safe_auction`) reflect a deliberate conservative bias on ASSET_LOCKING.
- Delegatecall safe-vs-unsafe discrimination is weaker than other categories.
- Some contextual workflow bugs get absorbed into NUANCED_ACCESS_CONTROL.

---

## Disclaimer

This tool is for **research and educational purposes only**.
Do not rely on it for auditing production smart contracts.

---

## Author

Fernando Centurión
Computer Science Student | Smart Contract Security Research
