---
marp: true
theme: default
paginate: true
backgroundColor: #fff
style: |
  section {
    font-family: 'Segoe UI', Arial, sans-serif;
  }
  h1 {
    color: #4051B5;
  }
  h2 {
    color: #333;
  }
  code {
    background-color: #f5f5f5;
    border-radius: 4px;
    padding: 2px 6px;
  }
  pre {
    background-color: #1e1e1e;
    border-radius: 8px;
  }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
  }
  .highlight {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 20px;
    border-radius: 8px;
  }
---

# Taint Analysis Masterclass

## Detecting Security Vulnerabilities Through Dataflow Analysis

**Laurent Giovannoni**

---

# Agenda

1. **What is Taint Analysis?**
2. **The Three Tools: Pysa, CodeQL, Semgrep**
3. **Live Demo: VulnShop**
4. **Benchmark Results**
5. **Enterprise Integration**
6. **Q&A**

---

# The Problem

## 70% of vulnerabilities are injection attacks

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Server-Side Request Forgery (SSRF)

**Common pattern:** User input → Dangerous operation

---

# What is Taint Analysis?

```
┌──────────┐     ┌─────────────┐     ┌──────────┐
│  SOURCE  │ ──▶ │ PROPAGATION │ ──▶ │   SINK   │
│  (input) │     │ (processing)│     │(dangerous)│
└──────────┘     └─────────────┘     └──────────┘
```

**Source:** Where untrusted data enters (HTTP requests, files, DB)
**Sink:** Dangerous operation (SQL query, shell command, HTML output)
**Sanitizer:** Function that cleans/validates data

---

# Vulnerable Code Example

```python
def login(request):
    username = request.POST['username']  # SOURCE

    query = f"SELECT * FROM users WHERE name = '{username}'"

    cursor.execute(query)  # SINK
```

**Attack:** `username = "admin'--"`

**Result:** Authentication bypass!

---

# Safe Code Example

```python
def login(request):
    username = request.POST['username']  # SOURCE

    query = "SELECT * FROM users WHERE name = %s"

    cursor.execute(query, [username])  # SANITIZED
```

**Parameterized query = No injection**

---

# The Three Tools

| Tool | Developer | Strength |
|------|-----------|----------|
| **Pysa** | Meta | Deep inter-procedural analysis |
| **CodeQL** | GitHub | Most powerful queries |
| **Semgrep** | Semgrep Inc. | Fast, simple rules |

---

# Pysa (Meta)

## Python Static Analyzer

```python
# Define source
def django.http.request.HttpRequest.GET.__getitem__(
    self, key
) -> TaintSource[UserControlled]: ...

# Define sink
def cursor.execute(
    self, sql: TaintSink[SQL]
): ...
```

**Best for:** Complex Python taint flows

---

# CodeQL (GitHub)

## Code as Data

```sql
class SqlInjectionConfig extends TaintTracking::Configuration {
  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call c | c.getFunc().getName() = "execute" |
      sink.asExpr() = c.getArg(0))
  }
}
```

**Best for:** Deep semantic analysis

---

# Semgrep

## Pattern Matching + Taint Mode

```yaml
rules:
  - id: sql-injection
    mode: taint
    pattern-sources:
      - pattern: request.GET[...]
    pattern-sinks:
      - pattern: cursor.execute($QUERY)
    message: SQL injection vulnerability
    severity: ERROR
```

**Best for:** Fast CI/CD feedback

---

# VulnShop: Our Test Target

## Deliberately Vulnerable E-commerce App

16 vulnerabilities across:

- Authentication
- Product catalog
- Shopping cart
- Admin panel
- Webhooks
- API

---

# Demo: Finding SQL Injection

```bash
# Semgrep (5 seconds)
semgrep --config rules/ vulnerable-app/

# Pysa (45 seconds)
pyre analyze

# CodeQL (2 minutes)
codeql database analyze db queries/
```

---

# Benchmark Results

| Tool | Detection Rate | Time | FP Rate |
|------|:--------------:|:----:|:-------:|
| CodeQL | 87.5% | 2m 15s | 6.7% |
| Pysa | 75.0% | 45s | 7.7% |
| Semgrep | 68.75% | 5s | 15.4% |

**Combined:** 93.75% (15/16)

---

# Detection Matrix

| Vulnerability | Pysa | CodeQL | Semgrep |
|---------------|:----:|:------:|:-------:|
| SQL Injection | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ |
| XSS | ✅ | ✅ | ✅ |
| SSRF | ✅ | ✅ | ✅ |
| Deserialization | ✅ | ✅ | ✅ |
| IDOR | ⚠️ | ⚠️ | ❌ |

---

# Recommended Strategy

```
┌─────────────────────────────────────────────┐
│  PR Created                                 │
│      ↓                                      │
│  Semgrep (5s) ──▶ Block on critical         │
│      ↓                                      │
│  Merge to main                              │
│      ↓                                      │
│  Pysa (45s) ──▶ Full taint analysis         │
│      ↓                                      │
│  CodeQL (nightly) ──▶ Deep analysis         │
└─────────────────────────────────────────────┘
```

---

# CI/CD Integration

```yaml
# GitHub Actions
- name: Semgrep
  uses: returntocorp/semgrep-action@v1
  with:
    config: p/security-audit

- name: CodeQL
  uses: github/codeql-action/analyze@v3
```

---

# Key Takeaways

1. **Taint analysis tracks data flow** from sources to sinks
2. **Combine tools** for best coverage
3. **Fast tools for PRs**, deep tools for releases
4. **Baselines** manage existing issues
5. **Custom rules** for business logic

---

# Resources

- **GitHub:** github.com/laugiov/code-safety
- **Semgrep:** semgrep.dev
- **CodeQL:** codeql.github.com
- **Pysa:** pyre-check.org

---

# Questions?

## Thank you!

**Contact:**
- GitHub: @laugiov
- Project: taint-analysis-masterclass

---

# Appendix: Quick Reference

## Semgrep
```bash
pip install semgrep
semgrep --config "p/python" .
```

## Pysa
```bash
pip install pyre-check
pyre analyze
```

## CodeQL
```bash
codeql database create db --language=python
codeql database analyze db queries/
```
