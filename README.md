# Leke AST Code Inspector — Static Guardrail Analyzer

A static code analysis utility using Python's standard `ast` (Abstract Syntax Tree) module. Parses Python files and PR diffs to automatically detect critical security risks and dangerous execution patterns before code reaches production or is executed in agent environments.

## Analyzed Patterns
- **Dangerous Dynamic Evaluation**: Detects `eval()`, `exec()`, `compile()`.
- **Command Injection**: Detects `os.system()` and `subprocess` with `shell=True`.
- **SQL Injections**: Detects dynamic f-string and `%` string formatting inside database `.execute()` calls.
- **Hardcoded Secrets**: Identifies plain-text API keys, JWT tokens, and passwords assigned to variables.

## Quick Start
```bash
# Run demo on sample vulnerable script
python main.py

# Run unit tests
pytest test_inspector.py -v
```
