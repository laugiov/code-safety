---
title: Semgrep Taint Mode
description: Dataflow tracking with Semgrep taint analysis
---

# Semgrep Taint Mode

Taint mode enables Semgrep to track data flow from sources (user input) to sinks (dangerous operations), detecting vulnerabilities that simple pattern matching cannot find.

## Taint Mode Basics

### Enabling Taint Mode

Add `mode: taint` to your rule:

```yaml
rules:
  - id: sql-injection-taint
    mode: taint
    message: SQL injection vulnerability
    severity: ERROR
    languages: [python]
    pattern-sources:
      - pattern: request.GET[...]
    pattern-sinks:
      - pattern: cursor.execute(...)
```

### Components

| Component | Purpose |
|-----------|---------|
| `pattern-sources` | Where tainted data originates |
| `pattern-sinks` | Dangerous operations to protect |
| `pattern-sanitizers` | Functions that clean data |
| `pattern-propagators` | How taint flows through operations |

## Defining Sources

### HTTP Request Sources

```yaml
pattern-sources:
  # Django
  - pattern: request.GET[...]
  - pattern: request.GET.get(...)
  - pattern: request.POST[...]
  - pattern: request.POST.get(...)
  - pattern: request.COOKIES[...]
  - pattern: request.COOKIES.get(...)
  - pattern: request.body
  - pattern: request.META[...]

  # Flask
  - pattern: flask.request.args.get(...)
  - pattern: flask.request.form.get(...)
  - pattern: flask.request.json

  # FastAPI
  - pattern: $PARAM  # Path parameters
    pattern-inside: |
      @app.$METHOD("/{$PARAM}")
      def $FUNC($PARAM, ...):
        ...
```

### Database Sources

```yaml
pattern-sources:
  # Django ORM
  - pattern: $MODEL.objects.get(...)
  - pattern: $MODEL.objects.filter(...)
  - pattern: $MODEL.objects.all()

  # Raw queries
  - pattern: cursor.fetchone()
  - pattern: cursor.fetchall()
```

### File Sources

```yaml
pattern-sources:
  - pattern: open($PATH).read()
  - pattern: $FILE.read()
  - pattern: $FILE.readline()
```

### Environment Sources

```yaml
pattern-sources:
  - pattern: os.environ[...]
  - pattern: os.environ.get(...)
  - pattern: os.getenv(...)
```

## Defining Sinks

### SQL Sinks

```yaml
pattern-sinks:
  - pattern: $CURSOR.execute($QUERY, ...)
    focus-metavariable: $QUERY
  - pattern: $CURSOR.executemany($QUERY, ...)
    focus-metavariable: $QUERY
  - pattern: $MODEL.objects.raw($QUERY, ...)
    focus-metavariable: $QUERY
  - pattern: $QS.extra(where=[$WHERE], ...)
    focus-metavariable: $WHERE
```

### Command Execution Sinks

```yaml
pattern-sinks:
  - pattern: os.system($CMD)
    focus-metavariable: $CMD
  - pattern: os.popen($CMD, ...)
    focus-metavariable: $CMD
  - pattern: subprocess.run($CMD, ..., shell=True, ...)
    focus-metavariable: $CMD
  - pattern: subprocess.Popen($CMD, ..., shell=True, ...)
    focus-metavariable: $CMD
```

### XSS Sinks

```yaml
pattern-sinks:
  - pattern: HttpResponse($CONTENT, ...)
    focus-metavariable: $CONTENT
  - pattern: render(request, $TEMPLATE, $CONTEXT, ...)
    focus-metavariable: $CONTEXT
  - pattern: $TEMPLATE.render($CONTEXT)
    focus-metavariable: $CONTEXT
```

### File System Sinks

```yaml
pattern-sinks:
  - pattern: open($PATH, ...)
    focus-metavariable: $PATH
  - pattern: os.path.join($BASE, $PATH, ...)
    focus-metavariable: $PATH
  - pattern: shutil.copy($SRC, $DST, ...)
    focus-metavariable: $DST
```

### SSRF Sinks

```yaml
pattern-sinks:
  - pattern: requests.get($URL, ...)
    focus-metavariable: $URL
  - pattern: requests.post($URL, ...)
    focus-metavariable: $URL
  - pattern: urllib.request.urlopen($URL, ...)
    focus-metavariable: $URL
  - pattern: httpx.get($URL, ...)
    focus-metavariable: $URL
```

## Defining Sanitizers

### Type Conversion Sanitizers

```yaml
pattern-sanitizers:
  - pattern: int(...)
  - pattern: float(...)
  - pattern: bool(...)
  - pattern: uuid.UUID(...)
```

### Encoding Sanitizers

```yaml
pattern-sanitizers:
  # HTML escaping
  - pattern: django.utils.html.escape(...)
  - pattern: markupsafe.escape(...)
  - pattern: html.escape(...)

  # URL encoding
  - pattern: urllib.parse.quote(...)
  - pattern: urllib.parse.urlencode(...)

  # SQL parameterization (implicit)
  - patterns:
      - pattern: $CURSOR.execute($QUERY, $PARAMS)
      - focus-metavariable: $PARAMS
```

### Validation Sanitizers

```yaml
pattern-sanitizers:
  # Path sanitization
  - pattern: os.path.basename(...)
  - pattern: os.path.normpath(...)

  # Input validation
  - pattern: re.match($PATTERN, ...)
  - pattern: re.fullmatch($PATTERN, ...)

  # Custom validators
  - pattern: validate_input(...)
  - pattern: sanitize_html(...)
```

### Conditional Sanitizers

```yaml
pattern-sanitizers:
  # Only sanitize if validation passes
  - patterns:
      - pattern: |
          if is_valid($X):
            ...
      - focus-metavariable: $X
```

## Defining Propagators

Propagators describe how taint flows through operations:

### String Operations

```yaml
pattern-propagators:
  # String concatenation
  - pattern: $Y = $X + ...
    from: $X
    to: $Y

  # Format strings
  - pattern: $Y = f"...{$X}..."
    from: $X
    to: $Y

  - pattern: $Y = "...".format(..., $X, ...)
    from: $X
    to: $Y

  - pattern: $Y = "..." % $X
    from: $X
    to: $Y

  # String methods
  - pattern: $Y = $X.strip()
    from: $X
    to: $Y

  - pattern: $Y = $X.lower()
    from: $X
    to: $Y

  - pattern: $Y = $X.upper()
    from: $X
    to: $Y
```

### Collection Operations

```yaml
pattern-propagators:
  # List operations
  - pattern: $LIST.append($X)
    from: $X
    to: $LIST

  - pattern: $Y = $LIST[$INDEX]
    from: $LIST
    to: $Y

  # Dictionary operations
  - pattern: $DICT[$KEY] = $X
    from: $X
    to: $DICT

  - pattern: $Y = $DICT[$KEY]
    from: $DICT
    to: $Y

  - pattern: $Y = $DICT.get($KEY, ...)
    from: $DICT
    to: $Y
```

### JSON Operations

```yaml
pattern-propagators:
  # JSON parsing preserves taint
  - pattern: $Y = json.loads($X)
    from: $X
    to: $Y

  - pattern: $Y = json.dumps($X)
    from: $X
    to: $Y

  # Dictionary access from JSON
  - pattern: $Y = $JSON[$KEY]
    from: $JSON
    to: $Y
```

## Complete Taint Rules

### SQL Injection

```yaml
rules:
  - id: sql-injection-complete
    mode: taint
    message: |
      SQL injection vulnerability detected.
      User input flows from $SOURCE to SQL execution without proper sanitization.
      Fix: Use parameterized queries with placeholders.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-89"
      owasp: "A03:2021"

    pattern-sources:
      - pattern: request.GET[...]
      - pattern: request.GET.get(...)
      - pattern: request.POST[...]
      - pattern: request.POST.get(...)
      - pattern: request.COOKIES[...]

    pattern-sinks:
      - pattern: $CURSOR.execute($QUERY)
        focus-metavariable: $QUERY
      - pattern: $CURSOR.execute($QUERY, ...)
        focus-metavariable: $QUERY
      - pattern: $MODEL.objects.raw($QUERY, ...)
        focus-metavariable: $QUERY

    pattern-sanitizers:
      - pattern: int(...)
      - pattern: float(...)
      - patterns:
          - pattern: $CURSOR.execute($Q, $PARAMS)
          - focus-metavariable: $PARAMS

    pattern-propagators:
      - pattern: $Y = f"...{$X}..."
        from: $X
        to: $Y
      - pattern: $Y = "...".format(..., $X, ...)
        from: $X
        to: $Y
      - pattern: $Y = $X + ...
        from: $X
        to: $Y
```

### Command Injection

```yaml
rules:
  - id: command-injection-complete
    mode: taint
    message: |
      Command injection vulnerability detected.
      User input flows to shell command execution.
      Fix: Use subprocess with shell=False and pass arguments as a list.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-78"
      owasp: "A03:2021"

    pattern-sources:
      - pattern: request.GET[...]
      - pattern: request.GET.get(...)
      - pattern: request.POST[...]
      - pattern: request.POST.get(...)

    pattern-sinks:
      - pattern: os.system($CMD)
        focus-metavariable: $CMD
      - pattern: os.popen($CMD, ...)
        focus-metavariable: $CMD
      - pattern: subprocess.run($CMD, ..., shell=True, ...)
        focus-metavariable: $CMD
      - pattern: subprocess.call($CMD, ..., shell=True, ...)
        focus-metavariable: $CMD
      - pattern: subprocess.Popen($CMD, ..., shell=True, ...)
        focus-metavariable: $CMD

    pattern-sanitizers:
      - pattern: shlex.quote(...)
      - pattern: shlex.split(...)

    pattern-propagators:
      - pattern: $Y = f"...{$X}..."
        from: $X
        to: $Y
      - pattern: $Y = "...".format(..., $X, ...)
        from: $X
        to: $Y
```

### SSRF

```yaml
rules:
  - id: ssrf-complete
    mode: taint
    message: |
      Server-Side Request Forgery (SSRF) vulnerability detected.
      User input controls the URL of a server-side HTTP request.
      Fix: Validate URLs against an allowlist of trusted domains.
    severity: ERROR
    languages: [python]
    metadata:
      cwe: "CWE-918"
      owasp: "A10:2021"

    pattern-sources:
      - pattern: request.GET[...]
      - pattern: request.GET.get(...)
      - pattern: request.POST[...]
      - pattern: request.POST.get(...)
      - pattern: json.loads(request.body)[...]

    pattern-sinks:
      - pattern: requests.get($URL, ...)
        focus-metavariable: $URL
      - pattern: requests.post($URL, ...)
        focus-metavariable: $URL
      - pattern: requests.put($URL, ...)
        focus-metavariable: $URL
      - pattern: requests.delete($URL, ...)
        focus-metavariable: $URL
      - pattern: urllib.request.urlopen($URL, ...)
        focus-metavariable: $URL

    pattern-sanitizers:
      - pattern: validate_url(...)
      - pattern: is_safe_url(...)
      - patterns:
          - pattern: |
              if $URL.startswith($ALLOWED):
                ...
          - focus-metavariable: $URL
```

## Testing Taint Rules

### Test File Structure

```python
# tests/sql-injection-taint.py

# ruleid: sql-injection-complete
def vulnerable_search(request):
    query = request.GET['q']
    cursor.execute(f"SELECT * FROM products WHERE name = '{query}'")

# ok: sql-injection-complete
def safe_search(request):
    query = request.GET['q']
    cursor.execute("SELECT * FROM products WHERE name = %s", [query])

# ok: sql-injection-complete
def safe_with_int(request):
    product_id = int(request.GET['id'])
    cursor.execute(f"SELECT * FROM products WHERE id = {product_id}")

# ruleid: sql-injection-complete
def vulnerable_format(request):
    name = request.POST.get('name')
    query = "SELECT * FROM users WHERE name = '{}'".format(name)
    cursor.execute(query)
```

### Running Tests

```bash
# Test all rules
semgrep --test rules/

# Test specific rule
semgrep --test rules/sql-injection.yml

# Verbose test output
semgrep --test --verbose rules/
```

## Performance Optimization

### Limit Source Scope

```yaml
# More efficient: specific source patterns
pattern-sources:
  - pattern: request.GET.get("query")

# Less efficient: broad patterns
pattern-sources:
  - pattern: request.$METHOD(...)
```

### Use Focus Metavariables

```yaml
# Always focus on the relevant part of the sink
pattern-sinks:
  - pattern: cursor.execute($QUERY, $PARAMS)
    focus-metavariable: $QUERY  # Only track flow to $QUERY
```

### Minimize Propagators

```yaml
# Only add propagators that Semgrep doesn't handle automatically
pattern-propagators:
  # Semgrep handles basic string operations
  # Only add custom/unusual propagation
  - pattern: $Y = custom_transform($X)
    from: $X
    to: $Y
```

## Next Steps

- [Writing Rules](rules.md) - Rule fundamentals
- [Quick Start](quickstart.md) - Get running fast
- [Semgrep Overview](index.md) - Return to main guide
