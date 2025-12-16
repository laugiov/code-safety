---
title: Writing Semgrep Rules
description: Create custom Semgrep rules for security analysis
---

# Writing Semgrep Rules

Semgrep uses a simple, YAML-based rule format that makes writing custom security rules accessible to developers. This guide covers everything from basic patterns to advanced techniques.

## Rule Structure

Every Semgrep rule follows this structure:

```yaml
rules:
  - id: unique-rule-identifier
    message: What this rule detects and why it matters
    severity: ERROR | WARNING | INFO
    languages:
      - python
    pattern: code.to.match(...)
```

### Metadata Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier (use kebab-case) |
| `message` | Yes | Human-readable explanation |
| `severity` | Yes | ERROR, WARNING, or INFO |
| `languages` | Yes | List of target languages |
| `pattern` | Varies | Code pattern to match |

### Extended Metadata

```yaml
rules:
  - id: sql-injection-format-string
    message: >
      User input in SQL query via f-string creates SQL injection vulnerability.
      Use parameterized queries instead.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89: SQL Injection"
      owasp: "A03:2021 - Injection"
      category: security
      technology:
        - django
        - python
      confidence: HIGH
      likelihood: HIGH
      impact: HIGH
      subcategory:
        - vuln
      references:
        - https://owasp.org/Top10/A03_2021-Injection/
    pattern: ...
```

## Pattern Types

### Basic Pattern

Matches exact code structure:

```yaml
rules:
  - id: dangerous-eval
    pattern: eval($X)
    message: Avoid eval() - can execute arbitrary code
    severity: ERROR
    languages: [python]
```

This matches:
- `eval(user_input)`
- `eval("code")`
- `eval(x + y)`

### Pattern-Either

Match any of multiple patterns:

```yaml
rules:
  - id: dangerous-exec-functions
    pattern-either:
      - pattern: eval($X)
      - pattern: exec($X)
      - pattern: compile($X, ...)
    message: Dangerous code execution function
    severity: ERROR
    languages: [python]
```

### Pattern-Inside

Match pattern only within a specific context:

```yaml
rules:
  - id: sql-in-view
    patterns:
      - pattern: cursor.execute($QUERY)
      - pattern-inside: |
          def $FUNC(request, ...):
            ...
    message: Raw SQL in Django view
    severity: WARNING
    languages: [python]
```

### Pattern-Not

Exclude certain patterns:

```yaml
rules:
  - id: sql-injection-not-parameterized
    patterns:
      - pattern: cursor.execute($QUERY)
      - pattern-not: cursor.execute($QUERY, $PARAMS)
    message: SQL query without parameters
    severity: ERROR
    languages: [python]
```

### Pattern-Not-Inside

Exclude matches within context:

```yaml
rules:
  - id: logging-outside-try
    patterns:
      - pattern: logger.exception(...)
      - pattern-not-inside: |
          try:
            ...
          except ...:
            ...
    message: logger.exception outside exception handler
    severity: WARNING
    languages: [python]
```

## Metavariables

### Basic Metavariables

`$VAR` matches any expression:

```yaml
pattern: os.system($CMD)
# Matches: os.system("ls"), os.system(user_input), os.system(f"rm {path}")
```

### Named Metavariables

Use descriptive names:

```yaml
pattern: requests.get($URL, verify=$VERIFY)
# Matches and captures $URL and $VERIFY for use in message
message: HTTP request to $URL with verify=$VERIFY
```

### Typed Metavariables

Restrict to specific types:

```yaml
pattern: |
  def $FUNC(..., password: str = $DEFAULT, ...):
    ...
# Only matches functions with string default for password
```

### Metavariable Comparison

```yaml
rules:
  - id: comparison-to-none
    patterns:
      - pattern: $X == None
      - metavariable-comparison:
          metavariable: $X
          comparison: $X != "None"
    message: Use 'is None' instead of '== None'
    severity: INFO
    languages: [python]
```

### Metavariable Regex

```yaml
rules:
  - id: hardcoded-secret
    patterns:
      - pattern: $VAR = "..."
      - metavariable-regex:
          metavariable: $VAR
          regex: (?i)(password|secret|api_key|token)
    message: Possible hardcoded secret in $VAR
    severity: ERROR
    languages: [python]
```

## VulnShop Security Rules

### SQL Injection Rule

```yaml
rules:
  - id: sql-injection-format-string
    message: >
      SQL injection vulnerability: user input flows to SQL query via format string.
      Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021"
      category: security
    pattern-either:
      # f-string in execute
      - pattern: $CURSOR.execute(f"...{$INPUT}...")
      # .format() in execute
      - pattern: $CURSOR.execute("...".format(..., $INPUT, ...))
      # % formatting in execute
      - pattern: $CURSOR.execute("..." % $INPUT)
      # Concatenation
      - pattern: $CURSOR.execute("..." + $INPUT + "...")
```

### Command Injection Rule

```yaml
rules:
  - id: command-injection
    message: >
      Command injection vulnerability: user input in shell command.
      Use subprocess with shell=False and pass arguments as list.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-78"
      owasp: "A03:2021"
    pattern-either:
      - pattern: os.system($CMD)
      - pattern: os.popen($CMD)
      - pattern: subprocess.run($CMD, shell=True, ...)
      - pattern: subprocess.call($CMD, shell=True, ...)
      - pattern: subprocess.Popen($CMD, shell=True, ...)
```

### XSS Rule

```yaml
rules:
  - id: xss-django-response
    message: >
      Potential XSS: untrusted data in HttpResponse without escaping.
      Use Django templates with auto-escaping or django.utils.html.escape().
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-79"
      owasp: "A03:2021"
    patterns:
      - pattern-either:
          - pattern: HttpResponse($DATA)
          - pattern: HttpResponse(content=$DATA)
      - pattern-not: HttpResponse(..., content_type="application/json", ...)
      - pattern-not: HttpResponse(..., content_type="text/plain", ...)
```

### SSRF Rule

```yaml
rules:
  - id: ssrf-requests
    message: >
      Potential SSRF: user-controlled URL in HTTP request.
      Validate URLs against allowlist before making requests.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-918"
      owasp: "A10:2021"
    pattern-either:
      - pattern: requests.get($URL, ...)
      - pattern: requests.post($URL, ...)
      - pattern: requests.put($URL, ...)
      - pattern: requests.delete($URL, ...)
      - pattern: urllib.request.urlopen($URL, ...)
      - pattern: httpx.get($URL, ...)
```

### Path Traversal Rule

```yaml
rules:
  - id: path-traversal
    message: >
      Potential path traversal: user input used in file path.
      Use os.path.basename() or validate path doesn't escape base directory.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-22"
      owasp: "A01:2021"
    pattern-either:
      - pattern: open($PATH, ...)
      - pattern: os.path.join($BASE, $PATH)
      - pattern: pathlib.Path($PATH)
      - pattern: shutil.copy($SRC, $DST)
```

### Insecure Deserialization Rule

```yaml
rules:
  - id: insecure-deserialization
    message: >
      Insecure deserialization: pickle/yaml can execute arbitrary code.
      Use json for data serialization or yaml.safe_load().
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-502"
      owasp: "A08:2021"
    pattern-either:
      - pattern: pickle.loads($DATA)
      - pattern: pickle.load($FILE)
      - pattern: yaml.load($DATA)
      - pattern: yaml.load($DATA, Loader=yaml.Loader)
      - pattern: yaml.unsafe_load($DATA)
```

### Hardcoded Secrets Rule

```yaml
rules:
  - id: hardcoded-secret
    message: >
      Hardcoded secret detected. Use environment variables or secret management.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-798"
      owasp: "A07:2021"
    pattern-either:
      - pattern: $VAR = "..."
      - pattern: $DICT["$KEY"] = "..."
    metavariable-regex:
      metavariable: $VAR
      regex: (?i)(password|passwd|secret|api_key|apikey|token|auth)
    pattern-not:
      - pattern: $VAR = ""
      - pattern: $VAR = "..."  # Placeholder
```

## Taint Mode

Semgrep's taint mode tracks data flow from sources to sinks:

```yaml
rules:
  - id: sql-injection-taint
    message: User input flows to SQL query
    severity: ERROR
    languages: [python]
    mode: taint
    pattern-sources:
      - pattern: request.GET.get(...)
      - pattern: request.POST.get(...)
      - pattern: request.GET[...]
      - pattern: request.POST[...]
    pattern-sinks:
      - pattern: $CURSOR.execute($QUERY, ...)
        focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern: int(...)
      - pattern: float(...)
```

### Advanced Taint Configuration

```yaml
rules:
  - id: xss-taint-tracking
    message: XSS vulnerability detected via taint tracking
    severity: ERROR
    languages: [python]
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: request.GET.get(...)
              - pattern: request.POST.get(...)
              - pattern: request.COOKIES.get(...)
          - pattern-not-inside: |
              @login_required
              def $FUNC(...):
                ...
    pattern-sinks:
      - pattern: HttpResponse($X, ...)
        focus-metavariable: $X
      - pattern: render(request, $TEMPLATE, $CONTEXT)
        focus-metavariable: $CONTEXT
    pattern-sanitizers:
      - pattern: escape(...)
      - pattern: mark_safe(...)  # Explicit marking
    pattern-propagators:
      - pattern: $Y = $X.format(...)
        from: $X
        to: $Y
      - pattern: $Y = f"...{$X}..."
        from: $X
        to: $Y
```

## Testing Rules

### Inline Tests

```yaml
rules:
  - id: sql-injection-test
    pattern: cursor.execute(f"...{$X}...")
    message: SQL injection
    severity: ERROR
    languages: [python]

# Test cases in same file
# ruleid: sql-injection-test
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# ok: sql-injection-test
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
```

### Running Tests

```bash
semgrep --test rules/
```

### Test File Structure

```
rules/
├── sql-injection.yml
└── tests/
    └── sql-injection/
        ├── vulnerable.py    # Should match
        └── safe.py          # Should not match
```

## Performance Tips

### Use Specific Patterns

```yaml
# BAD: Too generic
pattern: $F(...)

# GOOD: Specific function
pattern: cursor.execute(...)
```

### Limit Pattern Depth

```yaml
# BAD: Deep nesting
pattern: |
  def $F(...):
    for $X in $Y:
      if $COND:
        for $A in $B:
          $FUNC(...)

# GOOD: Focus on the issue
pattern: $FUNC(...)
```

### Use focus-metavariable

```yaml
# Focuses analysis on specific part
pattern-sinks:
  - pattern: cursor.execute($QUERY, $PARAMS)
    focus-metavariable: $QUERY
```

## Next Steps

- [Taint Mode](taint-mode.md) - Deep dive into dataflow tracking
- [Quick Start](quickstart.md) - Get running fast
- [Semgrep Overview](index.md) - Return to main guide
