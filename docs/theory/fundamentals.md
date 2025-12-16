---
title: Taint Analysis Fundamentals
description: Core concepts of taint analysis for application security
---

# Taint Analysis Fundamentals

This page covers the core concepts of taint analysis, providing the theoretical foundation for understanding how static analysis tools detect security vulnerabilities.

## What is Taint Analysis?

**Taint analysis** (also called **data flow analysis** or **information flow analysis**) is a technique for tracking how data flows through a program. In security contexts, it identifies paths where untrusted data can reach sensitive operations without proper sanitization.

### The Core Question

> "Can user-controlled data reach a security-sensitive operation without being validated or sanitized?"

If yes → **Potential Vulnerability**

## Fundamental Concepts

### 1. Sources (Taint Origins)

**Sources** are entry points where untrusted data enters the application.

| Source Type | Examples | Taint Level |
|-------------|----------|-------------|
| HTTP Parameters | `request.GET`, `request.POST` | High |
| Headers | `request.META`, cookies | High |
| URL Path | `request.path`, path parameters | High |
| File Uploads | `request.FILES` | High |
| External APIs | Third-party responses | Medium |
| Database | Data from other users | Medium |
| Environment | `os.environ` (if user-controlled) | Variable |

**Example - Django Sources:**
```python
# All of these are taint sources
username = request.GET.get('username')      # Query parameter
password = request.POST.get('password')     # Form data
session_id = request.COOKIES.get('sid')     # Cookie
user_agent = request.META.get('HTTP_USER_AGENT')  # Header
uploaded = request.FILES.get('document')    # File upload
```

### 2. Sinks (Security-Sensitive Operations)

**Sinks** are operations where tainted data could cause security issues.

| Sink Type | Operations | Vulnerability |
|-----------|------------|---------------|
| SQL Execution | `cursor.execute()`, raw queries | SQL Injection |
| Command Execution | `os.system()`, `subprocess` | Command Injection |
| File Operations | `open()`, `os.path.join()` | Path Traversal |
| HTML Rendering | `mark_safe()`, `format_html()` | XSS |
| HTTP Requests | `requests.get()`, `urllib` | SSRF |
| Deserialization | `pickle.loads()`, `yaml.load()` | RCE |
| Template Rendering | `Template()`, `render_template_string()` | SSTI |

**Example - Django Sinks:**
```python
# All of these are sinks
cursor.execute(query)           # SQL sink
os.system(command)              # Command sink
open(filepath)                  # File sink
mark_safe(html)                 # XSS sink
requests.get(url)               # SSRF sink
pickle.loads(data)              # Deserialization sink
Template(template_str).render() # SSTI sink
```

### 3. Taint Propagation

**Propagation** describes how taint spreads through the program.

#### Propagation Rules

```python
# Assignment propagates taint
user_input = request.GET.get('q')  # TAINTED
search_term = user_input           # TAINTED (propagated)

# String operations propagate taint
query = "SELECT * FROM users WHERE name = '" + user_input + "'"  # TAINTED

# Function returns propagate taint
def process(data):
    return data.upper()

result = process(user_input)  # TAINTED (taint flows through)

# Collections propagate taint
my_list = [user_input]        # List is TAINTED
my_dict = {'key': user_input} # Dict is TAINTED
```

#### Complex Propagation

```python
# Taint through control flow
if condition:
    value = user_input  # TAINTED
else:
    value = "safe"      # NOT TAINTED

# At merge point: value is POTENTIALLY TAINTED
# Conservative analysis treats it as TAINTED

# Taint through loops
for item in user_controlled_list:  # Each item is TAINTED
    process(item)
```

### 4. Sanitizers (Taint Removal)

**Sanitizers** are functions that clean or validate data, making it safe for specific sinks.

| Sanitizer | Effect | Target Sink |
|-----------|--------|-------------|
| `escape()` | HTML entity encoding | XSS |
| `int()` | Type conversion | SQL (numeric) |
| Parameterized queries | SQL escaping | SQL |
| `shlex.quote()` | Shell escaping | Command |
| `os.path.basename()` | Path component only | Path Traversal |
| Allow-list validation | Explicit checking | Any |

**Example - Sanitization:**
```python
from django.utils.html import escape

# BEFORE: Vulnerable to XSS
output = mark_safe(user_input)  # TAINTED → SINK = VULN

# AFTER: Sanitized
safe_output = escape(user_input)  # SANITIZED
output = mark_safe(safe_output)   # OK
```

## Taint Flow Analysis

### Basic Flow Pattern

```
┌──────────┐    ┌─────────────┐    ┌──────────┐
│  SOURCE  │───▶│ PROPAGATION │───▶│   SINK   │
│          │    │             │    │          │
│ request  │    │ variables   │    │ execute  │
│ .GET     │    │ functions   │    │ system   │
│ .POST    │    │ strings     │    │ open     │
└──────────┘    └─────────────┘    └──────────┘

     ↓                 ↓                 ↓
   TAINT             TRACK            DETECT
  (mark)           (follow)          (alert)
```

### Example: SQL Injection Flow

```python
def login(request):
    # STEP 1: SOURCE - User input enters application
    username = request.POST.get('username')  # TAINTED
    password = request.POST.get('password')  # TAINTED

    # STEP 2: PROPAGATION - Taint flows through operations
    query = f"SELECT * FROM users WHERE username = '{username}'"  # TAINTED

    # STEP 3: SINK - Tainted data reaches dangerous operation
    cursor.execute(query)  # VULNERABILITY: SQL Injection
```

### Analysis Visualization

```
login(request)
│
├─ username = request.POST.get('username')
│  └─ TAINT: UserControlled → username
│
├─ query = f"SELECT ... '{username}'"
│  └─ PROPAGATE: username → query (via f-string)
│
└─ cursor.execute(query)
   └─ SINK: SQL Execution
   └─ ALERT: UserControlled → SQL [CWE-89]
```

## Types of Taint Analysis

### 1. Intra-procedural Analysis

Analyzes taint flow within a single function.

```python
def vulnerable_function(request):
    user_input = request.GET.get('input')  # Source
    query = "SELECT * FROM t WHERE id = " + user_input  # Propagation
    cursor.execute(query)  # Sink
```

**Pros:** Fast, simpler
**Cons:** Misses cross-function flows

### 2. Inter-procedural Analysis

Tracks taint across function calls.

```python
def get_user_input(request):
    return request.GET.get('input')  # Source

def build_query(value):
    return "SELECT * FROM t WHERE id = " + value  # Propagation

def vulnerable_view(request):
    user_input = get_user_input(request)  # Flow point 1
    query = build_query(user_input)        # Flow point 2
    cursor.execute(query)                  # Sink
```

**Pros:** More accurate, catches complex flows
**Cons:** Slower, more complex

### 3. Context-Sensitive Analysis

Distinguishes different call sites for the same function.

```python
def process(data):
    return data.upper()

# Call site 1: Tainted
result1 = process(request.GET.get('input'))  # TAINTED

# Call site 2: Not tainted
result2 = process("safe_constant")  # NOT TAINTED
```

Context-sensitive analysis correctly identifies that `result1` is tainted but `result2` is not.

## Precision vs. Recall Trade-offs

### Definitions

| Metric | Definition | Goal |
|--------|------------|------|
| **Precision** | True Positives / All Reported | Reduce false positives |
| **Recall** | True Positives / All Actual | Find all vulnerabilities |

### Trade-off Spectrum

```
                    PRECISION ─────────────────▶

RECALL     Pattern Matching     Semantic Analysis     Formal Methods
  │        (Semgrep)            (CodeQL)             (Pysa)
  │
  │        Fast                 Balanced              Deep
  │        More FP              Moderate FP           Fewer FP
  │        Good coverage        Good coverage         May miss edge cases
  ▼
```

### Practical Considerations

1. **High Precision, Lower Recall**
   - Fewer false positives
   - May miss some real vulnerabilities
   - Good for: CI/CD blocking

2. **High Recall, Lower Precision**
   - Finds more vulnerabilities
   - More false positives to triage
   - Good for: Security audits

## Limitations of Taint Analysis

### 1. Reflection and Dynamic Code

```python
# Hard to analyze statically
attr_name = request.GET.get('attr')
getattr(obj, attr_name)  # What attribute is accessed?

# Dynamic function calls
func_name = request.GET.get('func')
globals()[func_name]()  # What function is called?
```

### 2. External Boundaries

```python
# Taint may not cross external calls
external_api_response = requests.get(external_url).json()
# Is this tainted? Depends on external system.
```

### 3. Implicit Flows

```python
# Information leaks through control flow
secret = get_secret()
if secret == user_guess:
    result = "correct"  # Information about secret leaked
else:
    result = "wrong"
```

### 4. Over/Under-Tainting

```python
# Over-tainting: False positive
password = request.POST.get('password')
password_hash = bcrypt.hashpw(password.encode(), salt)
# password_hash is marked tainted, but it's actually safe for logging

# Under-tainting: Missed vulnerability
safe_list = ['admin', 'user', 'guest']
if user_input in safe_list:
    # Analyzer might not track this validation
    use_safely(user_input)  # Could be missed as still tainted
```

## Best Practices

### 1. Defense in Depth

Don't rely solely on taint analysis. Combine with:
- Manual code review
- Dynamic testing (DAST)
- Runtime protection (RASP)

### 2. Minimize Taint Surface

```python
# BAD: Large taint surface
data = request.POST

# GOOD: Explicit, minimal sources
username = request.POST.get('username', '')[:50]  # Limited, validated
```

### 3. Sanitize at Boundaries

```python
# GOOD: Sanitize immediately when data enters
def clean_input(request):
    username = request.POST.get('username', '')
    return escape(username)[:100]  # Sanitized and bounded
```

### 4. Use Type-Safe Patterns

```python
# GOOD: Type safety prevents injection
user_id = int(request.GET.get('id', 0))  # Converts or raises
User.objects.get(pk=user_id)  # Safe: integer parameter
```

## Next Steps

- [Dataflow Analysis Deep Dive](dataflow.md)
- [Tool Comparison](../tools/comparison.md)
- [Vulnerability Types](../vulnerabilities/index.md)

---

*Understanding these fundamentals is essential for effectively using any taint analysis tool.*
