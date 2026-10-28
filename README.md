# 🛡️ Leke AST Code Inspector — Static Security Guardrail & Complexity Gate

> **Production-grade Python Abstract Syntax Tree (AST) static analyzer** designed for AI agent execution sandboxes, pre-commit guardrails, and CI/CD security pipelines. Detects Remote Code Execution (RCE), OS command injection, dynamic SQL concatenation, hardcoded secrets, and unsafe deserialization with **zero external dependencies**.

---

## 🏗️ Architecture Overview

Unlike regex-based linters that produce over 80% false positives (flagging variable names, comments, and strings), the **Leke AST Code Inspector** hooks directly into the **Python Compiler Frontend** (`ast.NodeVisitor`). It traverses the parsed syntax grammar tree to inspect node types, arguments, attributes, and call contexts deterministically.

```
                  ┌──────────────────────────────────────────────┐
                  │          Python Source Code / Diff           │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼ ast.parse()
                  ┌──────────────────────────────────────────────┐
                  │         Abstract Syntax Tree (AST)           │
                  └──────────────┬───────────────────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
  ┌─────────────────────────────┐ ┌─────────────────────────────┐
  │     ASTSecurityVisitor      │ │      ASTMetricsVisitor      │
  │  (Traverses Call, Assign,   │ │ (Calculates McCabe Branching│
  │   Try, Attribute nodes)     │ │  Depth, LOC, AST Node Count)│
  └──────────────┬──────────────┘ └──────────────┬──────────────┘
                 │                               │
                 ▼                               ▼
  ┌─────────────────────────────┐ ┌─────────────────────────────┐
  │  10 CWE/OWASP Guardrails    │ │   Maintainability Index     │
  │ (RCE, SQLi, Secrets, Pickles│ │ (Halstead Volume + Cyclo)   │
  └──────────────┬──────────────┘ └──────────────┬──────────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
  ┌─────────────────────────────────────────────────────────────┐
  │                 Unified Analysis Engine                     │
  │  • CLI Terminal Report with Colorized Badges & Fix Diffs    │
  │  • GitHub Code Scanning SARIF v2.1.0 Artifact               │
  │  • JSON Output for Automated Build Pipelines                │
  │  • Embedded Dark-Mode Interactive Browser Web Dashboard     │
  └─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Core Guardrails & Security Rulebook

All rules are mapped to formal **MITRE CWE** (Common Weakness Enumeration) and **OWASP Top 10** standards:

| Rule ID | Rule Identifier | Category | Severity | Standard | Target AST Nodes |
|---|---|---|---|---|---|
| **SEC-001** | `DANGEROUS_EVAL_EXEC` | Code Injection | **CRITICAL** | CWE-95 / OWASP A03 | `ast.Call` (`eval`, `exec`, `compile`, `__import__`) |
| **SEC-002** | `INSECURE_OS_COMMAND` | Command Injection | **HIGH** | CWE-78 / OWASP A03 | `ast.Call` (`os.system`, `os.popen`, `subprocess` with `shell=True`, `pty.spawn`) |
| **SEC-003** | `RAW_SQL_STRING_CONCATENATION` | SQL Injection | **CRITICAL** | CWE-89 / OWASP A03 | `ast.Call` (`.execute()`, `.executemany()` with `JoinedStr`, `BinOp %`, `BinOp +`) |
| **SEC-004** | `HARDCODED_CREDENTIAL` | Hardcoded Secrets | **HIGH** | CWE-798 / OWASP A07 | `ast.Assign` (Entropy detection on key/secret/token identifiers) |
| **SEC-005** | `INSECURE_DESERIALIZATION` | Object Deserialization | **CRITICAL** | CWE-502 / OWASP A08 | `ast.Call` (`pickle.loads`, `yaml.load` without `SafeLoader`) |
| **SEC-006** | `WEAK_CRYPTOGRAPHIC_HASH` | Cryptography | **MEDIUM** | CWE-327 / OWASP A02 | `ast.Call` (`hashlib.md5`, `hashlib.sha1`) |
| **SEC-007** | `DISABLED_TLS_VERIFICATION` | Network Security | **HIGH** | CWE-295 / OWASP A02 | `ast.Call` (`verify=False` in `requests`, `httpx`, `urllib3`) |
| **SEC-008** | `INSECURE_TEMP_FILE` | Race Condition (TOCTOU) | **MEDIUM** | CWE-377 / OWASP A01 | `ast.Call` (`tempfile.mktemp`) |
| **SEC-009** | `BLIND_EXCEPTION_SWALLOWING`| Error Handling | **LOW** | CWE-703 / OWASP A05 | `ast.Try` (Bare `except:` or `BaseException:` with `Pass`) |
| **SEC-010** | `PRODUCTION_DEBUG_FLAG` | Misconfiguration | **MEDIUM** | CWE-489 / OWASP A05 | `ast.Call` (`debug=True` in framework runners) |

---

## 📊 Code Complexity & Structural Quality Engine

Beyond vulnerability detection, the engine evaluates software maintainability:
- **McCabe Cyclomatic Complexity ($v(G)$)**: Recursively counts independent execution paths (`If`, `For`, `While`, `Try`, `With`, `Assert`, `BoolOp and/or`).
- **AST Node Density & Recursion Depth**: Detects deeply nested code architectures.
- **Maintainability Index (MI)**: Computes a normalized score (0–100) combining LOC, cyclomatic branching, and estimated Halstead volume.

---

## 🚀 Quick Start & Demo Commands

The engine is built strictly on Python's **Standard Library**. No `pip install` required to run!

### 1. Interactive Web Demo (Browser UI)
Launch the dark-mode dashboard with real-time AST hierarchy visualization:
```bash
python main.py --serve
# Or specify a custom port
python main.py --serve --port 8080
```
Open **`http://localhost:8000`** in any browser.

> **Offline Resilient**: `index.html` also runs seamlessly when double-clicked directly via `file:///` without a server running!

### 2. Run CLI Guardrail on Sample Vulnerable AI Agent
```bash
python main.py
```

### 3. Scan a Specific File or Entire Directory
```bash
# Scan a single script
python main.py --file path/to/agent.py

# Recursively scan an entire codebase
python main.py --dir ./src
```

### 4. CI/CD Pipeline Gate with Exit Codes
Enforce zero CRITICAL or HIGH violations before merging a pull request:
```bash
python main.py --file src/app.py --fail-on HIGH
# Returns exit code 1 if CRITICAL or HIGH violations are found, 0 if clean.
```

### 5. Export GitHub Code Scanning SARIF Report
Generate standard **SARIF v2.1.0** (Static Analysis Results Interchange Format) for GitHub Actions:
```bash
python main.py --file agent_tool.py --format sarif > results.sarif
```

### 6. Run Full Unit Test Suite
```bash
python test_inspector.py
```

---

## 💡 Why AST vs. Regex? (Senior Talking Points)

| Dimension | Naive Regex (`re.search`) | AST NodeVisitor (`ast`) |
|---|---|---|
| **Context Awareness** | Blind to grammar. Flags `eval` inside comments or variable names like `eval_results = 5`. | Analyzes syntactical context. Differentiates between function definitions, variable names, and active call expressions. |
| **String Formatting in SQL** | Easily fooled by multi-line queries, concatenated strings, or `.format()`. | Accurately inspects `JoinedStr` (f-string) and `BinOp` (`%` / `+`) inside the target `.execute()` argument node. |
| **Security in AI Agent Loops** | Trivial for adversarial prompts or LLM-generated code to obfuscate around regex. | Operates on the final compiled syntax tree, neutralizing regex bypasses. |
| **Performance** | $O(M \times N)$ regex engine backtracking. | $O(N)$ single-pass compiler AST traversal (< 10ms for 1,000 LOC). |
| **External Dependencies** | 0 | 0 (pure standard library). |

---

## 📂 Project Structure

```
leke-ast-code-inspector/
├── inspector.py          # Core AST analyzer, SecurityVisitor, MetricsVisitor, SARIF builder
├── main.py               # CLI tool, terminal report formatter, directory scanner
├── server.py             # Embedded HTTP server & REST API (/api/inspect, /api/rules)
├── index.html            # Dark-mode interactive web dashboard & AST tree explorer
├── test_inspector.py     # Comprehensive unit tests (15 test suites)
├── SENIOR_DEMO_SCRIPT.md # Presentation script & senior interview defense guide
└── README.md             # Architecture documentation
```
