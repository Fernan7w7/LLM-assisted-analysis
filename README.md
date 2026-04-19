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

test_regression.py        — 23-case regression test
run_baselines.py          — pipeline + Slither + Mythril comparison runner
ablation_models.py        — per-model ablation study (GPT / Claude / Gemini)
reports/                  — saved JSON and CSV results
```

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Fernan7w7/LLM-assisted-analysis.git
cd LLM-assisted-analysis
```

### 2. Create and activate virtual environment

```bash
python -m venv research-env
source research-env/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Slither (optional, for baseline comparison)

```bash
pip install slither-analyzer
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
```

---

## Environment Variables

Create a `.env` file in the project root:

```env
OPENAI_API_KEY=your_key_here
CLAUDE_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
```

---

## Usage

### Run the regression test (23 representative cases)

```bash
python test_regression.py
```

### Run the baseline comparison (pipeline vs Slither vs Mythril)

```bash
python run_baselines.py
```

### Run the model ablation study

```bash
python ablation_models.py --models gpt claude gemini
```

Results are saved to `reports/` with a timestamp.

### Analyze a single contract

```python
from pipeline.runner import analyze_contract
results = analyze_contract("path/to/contract.sol")
```

---

## Evaluation

Full results are documented in:

- `EVALUATION_REPORT.md` — dataset breakdown, regression results, baseline comparison, model ablation, design notes
- `NOVELTY_STATEMENT.md` — novelty claims, expected contributions, and honest limitations
- `reports/` — raw JSON and CSV output from each evaluation run

---

## Limitations

- Dataset is proof-of-concept scale (~27 contracts); statistical claims require ~90+ per-category samples.
- LLM outputs are non-deterministic; results may vary slightly across runs.
- No inter-procedural analysis — vulnerabilities that span multiple functions or contracts are out of scope.
- Two known false positives (`locking_03_safe_redeem`, `logic_05_safe_auction`) reflect a deliberate conservative bias on ASSET_LOCKING.

---

## Disclaimer

This tool is for **research and educational purposes only**.
Do not rely on it for auditing production smart contracts.

---

## Author

Fernando Centurión  
Computer Science Student | Smart Contract Security Research
