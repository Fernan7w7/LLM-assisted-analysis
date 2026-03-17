# LLM-Assisted Smart Contract Analyzer

A security-focused tool that explores how **Large Language Models (LLMs)** can assist in detecting **logic vulnerabilities in Ethereum smart contracts**, especially those that traditional static analyzers struggle to capture.

---

## Overview

Smart contract vulnerabilities are not limited to low-level bugs like reentrancy or overflow. Many real-world exploits arise from **logic flaws**, such as:

- Incorrect execution order
    
- Missing validation conditions
    
- Economic manipulation (e.g., AMM price abuse)
    
- Denial-of-Service via external dependencies
    

Traditional tools like Slither are excellent at detecting syntactic and pattern-based issues, but often miss these **context-aware vulnerabilities**.

This project investigates:

> **Can LLMs help detect these logic vulnerabilities more effectively?**

---

## Objectives

- Detect **logic-level vulnerabilities** in Solidity smart contracts
    
- Compare LLM-assisted analysis with traditional tools (e.g., Slither)
    
- Evaluate different LLM providers in terms of:
    
    - Detection capability
        
    - False positives
        
    - Consistency
        
    - Cost efficiency
        

---

## Key Idea

Instead of treating LLMs as black-box detectors, this project uses a **structured analysis pipeline**:

1. **Function-level analysis** (not full contract blobs)
    
2. **Scenario matching** — identify relevant patterns
    
3. **Property validation** — check for unsafe conditions
    
4. **Optional confirmation** — lightweight static checks
    

This approach improves reliability and reduces hallucinations.

---

## Architecture

```
Solidity Contract
        ↓
Function Extraction
        ↓
LLM Analysis (per vulnerability)
   ├─ Scenario Check
   ├─ Property Check
        ↓
(Optional for now) Static Confirmation
        ↓
Results Aggregation
        ↓
Report + Metrics
```

---

## Supported Vulnerabilities

Current focus is on **logic and context-aware vulnerabilities**, including:

- DoS by external contract
    
- Slippage (missing minimum output checks)
    
- Unauthorized token transfer
    
- Wrong checkpoint / interest order
    
- Front-running risks
    
- Price manipulation (AMM / buying)
    
- Centralization risks
    

> These are intentionally chosen because they are **not easily detected by traditional static analysis**

---

## Supported LLM Providers

- Claude (Anthropic)
    
- GPT (OpenAI)
    
- Gemini (Google)
    

All models are evaluated under:

- Same input
    
- Same prompt structure
    
- Same constraints (JSON output)
    

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Fernan7w7/LLM-assisted-analysis
cd LLM-assisted-analysis
```

### 2. Create virtual environment

```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Slither

```bash
pip install slither-analyzer
```

(Optional but recommended)

```bash
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
```

---

## Environment Variables

Create a `.env` file:

```env
CLAUDE_API_KEY=your_key_here
GPT_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
```

---

## Usage

Run analysis on a Solidity contract:

```bash
python scripts/llm_analyzer.py contracts/example.sol
```

---

## Output

The tool generates:

### Console Report

- Slither findings
    
- LLM findings per provider
    
- Cross-comparison table
    

### JSON Report

Saved in:

```
reports/llm_analysis_<contract>.json
```

Includes:

- Detected vulnerabilities
    
- Confidence levels
    
- Affected functions
    
- Model outputs
    

---

## Evaluation Metrics

The project focuses on:

- True Positives / False Positives
    
- Precision / Recall
    
- Model consistency (multi-run agreement)
    
- Cost per detection
    

---

## Limitations

- LLMs may hallucinate or overgeneralize
    
- No full data-flow analysis (lightweight checks only)
    
- Results depend on prompt quality
    
- Some vulnerabilities require cross-function reasoning
    

---

## Future Work

- Add dataset with labeled vulnerabilities
    
- Improve static confirmation layer
    
- Support multi-function / cross-contract analysis
    
- Integrate symbolic execution or fuzzing
    
- Optimize prompts for cost-performance tradeoff
    

---

## Inspiration

This project is inspired by research combining:

- Static analysis
    
- Program understanding
    
- LLM reasoning for security
    

---

## Contributing

Contributions are welcome!  
Feel free to open issues or submit pull requests.

---

## Disclaimer

This tool is for **research and educational purposes only**.  
Do not rely on it for auditing production smart contracts.

---

## Author

monsert
Computer Science Student | Smart Contract Security Enthusiast

---