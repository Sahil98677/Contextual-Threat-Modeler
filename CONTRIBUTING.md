# Contributing to Contextual Threat Modeler (CTM)

Thank you for your interest in contributing to CTM! Contributions that improve correctness, explainability, test coverage, documentation, and scanner compatibility are welcome.

## Before You Start

- Read the [README](README.md) to understand CTM's purpose, installation, and usage.
- Review [SECURITY.md](SECURITY.md) for responsible security reporting.
- For significant changes, open an issue or discussion first so the proposed approach can be agreed on before implementation.

CTM is a context-aware security decision engine. It consumes scanner and reconnaissance exports, enriches findings with context, and helps prioritize investigation. It is not a scanner and must not claim that a candidate attack path is a verified exploit chain unless the input evidence supports that conclusion.

## Development Setup

CTM supports Python 3.10 and newer.

1. Clone the repository and enter its directory:

   ```bash
   git clone https://github.com/Sahil98677/Contextual-Threat-Modeler.git
   cd Contextual-Threat-Modeler
   ```

2. Create and activate a virtual environment.

   **Windows PowerShell:**

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   **Linux, Kali Linux, or macOS:**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install the project and development dependencies:

   ```bash
   python -m pip install --upgrade pip
   python -m pip install -e ".[dev]"
   ```

4. Run CTM with the included synthetic sample data:

   ```bash
   ctm
   ```

## Tests and Validation

Run the test suite before submitting a change:

```bash
python -m pytest
```

For changes involving scanner ingestion, normalization, scoring, decisions, reporting, or attack-path correlation, add or update regression tests that cover the changed behavior and relevant edge cases.

The GitHub Actions CI workflow tests the supported Python versions. Make sure your changes pass locally and check that CI passes after opening a pull request.

## Contribution Guidelines

### General code changes

- Keep changes focused and avoid unrelated refactoring.
- Preserve existing CLI behavior and public interfaces unless a change is intentional and documented.
- Prefer deterministic, explainable behavior over hidden heuristics.
- Validate external input defensively; do not rely on Python truthiness for untrusted string values such as `"false"`.
- Handle malformed or incomplete scanner data safely and provide useful error messages.
- Do not silently discard important evidence or invent missing asset, vulnerability, or exploit details.
- Update relevant documentation when behavior, options, formats, or workflows change.

### Scanner adapters

When adding or changing an adapter:

- Follow the existing adapter interface and registry pattern.
- Normalize scanner-specific output into CTM's common input representation.
- Include a small synthetic fixture representative of the format.
- Add tests for valid input, missing or malformed fields, and important edge cases.
- Do not treat inventory data (such as an open port or detected service) as a vulnerability by itself.
- Document the accepted export format and any limitations.

### Risk scoring and threat mapping

- Keep risk factors explainable and covered by tests.
- Document changes to scoring thresholds, control modifiers, confidence, or decision rules.
- Keep STRIDE and MITRE ATT&CK enrichment separate from numeric risk calculations unless a deliberate, tested design change is proposed.
- Distinguish candidate correlations from verified attack paths; never overstate exploitability.

### Reports and sample data

- Use synthetic or properly sanitized data in tests, examples, screenshots, and documentation.
- Never commit credentials, API keys, access tokens, private customer data, or unapproved scan exports.
- Avoid adding unnecessary dependencies; explain the need for new dependencies in the pull request.

## Reporting Bugs and Requesting Features

When opening an issue, include the relevant details:

- CTM version or commit and Python version
- Operating system and command used
- Expected behavior and actual behavior
- A minimal reproduction, sanitized input, or synthetic fixture
- Relevant error output or test failure

Remove secrets, personal data, and sensitive target details before sharing logs or files. For suspected security vulnerabilities, follow [SECURITY.md](SECURITY.md) rather than publishing exploit details in a public issue.

## Pull Request Process

1. Create a focused branch for your change.
2. Make the change and add or update tests and documentation as needed.
3. Run `python -m pytest` and review the complete diff.
4. Use a clear commit message describing the change.
5. Open a pull request against `main` and explain:
   - What changed and why
   - How it was tested
   - Any compatibility or behavior changes
   - Any limitations or follow-up work
6. Respond to review feedback and ensure required CI checks pass.

A pull request may be revised or declined if it lacks tests for behavior changes, introduces unsupported claims, includes sensitive data, or expands scope without a clear reason.

## Documentation Contributions

Documentation improvements are welcome. Keep commands aligned with the current CLI implementation, identify synthetic examples as synthetic, and avoid promising features that are not implemented.

## License

By submitting a contribution, you agree that your contribution may be distributed under the repository's existing [MIT License](LICENSE).
