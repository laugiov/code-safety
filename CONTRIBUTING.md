# Contributing to Taint Analysis Masterclass

First off, thank you for considering contributing to Taint Analysis Masterclass! It's people like you that make this project a valuable resource for the security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Security Considerations](#security-considerations)

---

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When you create a bug report, include as many details as possible using our [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).

**Great bug reports include:**
- A clear and descriptive title
- Exact steps to reproduce the issue
- Expected vs. actual behavior
- Environment details (OS, Python version, tool versions)
- Relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- A clear and descriptive title
- Detailed description of the proposed functionality
- Explanation of why this enhancement would be useful
- Examples of how it would be used

### Adding New Vulnerabilities

One of the most valuable contributions is adding new vulnerabilities to VulnShop. To add a new vulnerability:

1. **Choose a vulnerability type** from OWASP Top 10 or CWE
2. **Implement the vulnerable code** in the appropriate module
3. **Document the vulnerability** with:
   - Inline code comments explaining the flaw
   - Taint flow (source → propagation → sink)
   - CWE and OWASP references
   - Exploitation proof-of-concept
4. **Add detection rules** for at least one tool (Pysa, CodeQL, or Semgrep)
5. **Update the ground truth** in `benchmarks/ground-truth/vulnerabilities.json`
6. **Add documentation** in `docs/en/vulnerabilities/`

### Improving Detection Rules

Contributions to improve detection accuracy are highly valued:

**For Pysa:**
- Add new source/sink/sanitizer models in `analysis/pysa/models/`
- Improve existing models for better precision
- Add model generators for common patterns

**For CodeQL:**
- Create new queries in `analysis/codeql/queries/`
- Improve existing queries to reduce false positives
- Add query suites for specific vulnerability categories

**For Semgrep:**
- Add new rules in `analysis/semgrep/rules/`
- Improve pattern matching accuracy
- Add rules for Django-specific patterns

### Improving Documentation

Documentation improvements are always welcome:

- Fix typos or grammatical errors
- Improve clarity of explanations
- Add examples or diagrams
- Translate documentation to other languages
- Add tutorials or guides

### Adding CVE Reproductions

Adding real-world CVE reproductions demonstrates practical applicability:

1. Create a directory under `benchmarks/cve-reproductions/CVE-XXXX-XXXXX/`
2. Include:
   - `README.md` with CVE details and explanation
   - `vulnerable_code.py` with the vulnerable pattern
   - `exploit.py` with exploitation PoC
   - `patch.py` with the secure version
3. Add detection rules for all three tools
4. Update documentation in `docs/en/benchmarks/cve-reproductions.md`

---

## Development Setup

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git
- Node.js 18+ (for documentation)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/laugiov/code-safety.git
cd taint-analysis-masterclass

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Start VulnShop
docker-compose up -d vulnshop
```

### Running Tests

```bash
# Run all tests
make test

# Run specific test suite
pytest tests/test_vulnerabilities.py

# Run linting
make lint

# Run type checking
make typecheck
```

### Running Analysis Tools

```bash
# Run Pysa
make analyze-pysa

# Run CodeQL
make analyze-codeql

# Run Semgrep
make analyze-semgrep

# Run all tools
make analyze-all
```

### Building Documentation

```bash
# Serve documentation locally
make docs-serve

# Build documentation
make docs-build
```

---

## Style Guidelines

### Python Code Style

We follow [PEP 8](https://pep8.org/) with the following specifics:

- **Line length**: 100 characters maximum
- **Imports**: Sorted with `isort`, grouped by standard/third-party/local
- **Formatting**: Enforced by `ruff format`
- **Docstrings**: Google style

```python
def example_function(param1: str, param2: int) -> bool:
    """Short description of function.

    Longer description if needed, explaining the function's
    purpose and any important details.

    Args:
        param1: Description of param1.
        param2: Description of param2.

    Returns:
        Description of return value.

    Raises:
        ValueError: When param2 is negative.
    """
    if param2 < 0:
        raise ValueError("param2 must be non-negative")
    return len(param1) > param2
```

### Vulnerable Code Comments

All vulnerable code must be clearly documented:

```python
def vulnerable_function(request):
    """
    VULNERABILITY: SQL Injection
    CWE-89: Improper Neutralization of Special Elements used in SQL Command
    OWASP: A03:2021 - Injection

    Taint Flow:
        Source: request.GET['id']
        Propagation: f-string formatting
        Sink: cursor.execute()

    Exploitation:
        curl "http://localhost:8000/endpoint?id=1' OR '1'='1"
    """
    user_id = request.GET.get('id')  # SOURCE: User-controlled input

    # VULNERABLE: Direct string interpolation in SQL
    query = f"SELECT * FROM users WHERE id = '{user_id}'"

    with connection.cursor() as cursor:
        cursor.execute(query)  # SINK: SQL execution
        return cursor.fetchone()
```

### Pysa Models

```python
# analysis/pysa/models/example.pysa

# Clear comments explaining the model
def module.function(
    self,
    param: TaintSource[UserControlled]  # Source annotation
): ...

def dangerous.function(
    data: TaintSink[SQL]  # Sink annotation
): ...
```

### CodeQL Queries

```ql
/**
 * @name Descriptive Query Name
 * @description Clear description of what the query detects
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id py/custom-query-id
 * @tags security
 *       external/cwe/cwe-XXX
 */

import python
import semmle.python.dataflow.new.DataFlow

// Query implementation with comments
class MyConfig extends TaintTracking::Configuration {
  // Configuration details
}
```

### Semgrep Rules

```yaml
rules:
  - id: descriptive-rule-id
    message: >-
      Clear message explaining the vulnerability and how to fix it.
      Include references to CWE or OWASP if applicable.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-XXX"
      owasp: "A0X:2021"
      category: security
      technology:
        - django
      references:
        - https://example.com/reference
    patterns:
      - pattern: |
          # Clear pattern with comments if complex
          dangerous_function($USER_INPUT)
      - metavariable-pattern:
          metavariable: $USER_INPUT
          patterns:
            - pattern: request.$METHOD.get(...)
```

---

## Commit Messages

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks
- `vuln`: Adding/modifying vulnerabilities in VulnShop
- `rule`: Adding/modifying analysis rules

### Examples

```bash
feat(vulnshop): add XXE vulnerability to API module

vuln(cart): implement insecure deserialization with pickle

rule(pysa): add Django ORM raw query sink model

docs(theory): add dataflow analysis explanation

fix(codeql): reduce false positives in SQL injection query
```

---

## Pull Request Process

### Before Submitting

1. **Create an issue** first to discuss significant changes
2. **Fork the repository** and create your branch from `main`
3. **Follow the style guidelines** described above
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Run the full test suite** and ensure it passes
7. **Run linting** and fix any issues

### Branch Naming

Use descriptive branch names:

```
feat/add-xxe-vulnerability
fix/pysa-false-positive-sql
docs/improve-getting-started
rule/semgrep-ssrf-detection
```

### PR Description

Use our [PR template](.github/PULL_REQUEST_TEMPLATE.md) and include:

- Clear description of changes
- Link to related issue(s)
- Type of change (bug fix, feature, etc.)
- Testing performed
- Checklist of completed items

### Review Process

1. **Automated checks** must pass (CI, linting, tests)
2. **At least one approval** required from maintainers
3. **Address all review comments** before merging
4. **Squash commits** if requested for cleaner history

---

## Security Considerations

### Responsible Vulnerability Development

When adding vulnerabilities to VulnShop:

1. **Document clearly** that the code is intentionally vulnerable
2. **Include remediation** examples showing the secure version
3. **Don't add backdoors** or capabilities beyond the documented vulnerability
4. **Test exploitation** in isolated environments only

### Reporting Security Issues

If you discover a security issue in the project infrastructure (not the intentional vulnerabilities):

1. **Do NOT** open a public issue
2. Use our [security vulnerability report template](.github/ISSUE_TEMPLATE/vulnerability_report.md)
3. Or email the maintainers directly
4. Allow time for a fix before public disclosure

### Ethical Use

By contributing, you agree that:

- Your contributions will be used for educational purposes
- You will not use knowledge gained here for malicious purposes
- You support responsible disclosure practices

---

## Recognition

Contributors will be recognized in:

- The project README
- Release notes for significant contributions
- The contributors page in documentation

---

## Questions?

If you have questions about contributing:

1. Check existing [issues](https://github.com/laugiov/code-safety/issues)
2. Read the documentation in the `docs/` directory
3. Open a [discussion](https://github.com/laugiov/code-safety/discussions)

---

Thank you for contributing to Taint Analysis Masterclass!
