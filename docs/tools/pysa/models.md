---
title: Writing Pysa Models
description: Create custom .pysa models for sources, sinks, and sanitizers
---

# Writing Pysa Models

Models are the heart of Pysa's taint analysis. They define where tainted data enters (sources), where it's dangerous (sinks), and how it's cleaned (sanitizers).

## Model File Basics

Model files use the `.pysa` extension and contain Python-like function signatures with taint annotations:

```python
# models/example.pysa

# Source: marks return value as tainted
def example.get_user_input() -> TaintSource[UserControlled]: ...

# Sink: marks parameter as dangerous
def example.execute_query(query: TaintSink[SQL]): ...

# Sanitizer: marks function as cleaning taint
def example.escape_html(text: TaintInTaintOut[LocalReturn, NoTaint]): ...
```

## Defining Sources

Sources mark where untrusted data enters your application.

### HTTP Request Sources

```python
# Django request parameters
def django.http.request.HttpRequest.GET.__getitem__(
    self,
    key: str
) -> TaintSource[UserControlled]: ...

def django.http.request.HttpRequest.POST.__getitem__(
    self,
    key: str
) -> TaintSource[UserControlled]: ...

def django.http.request.HttpRequest.GET.get(
    self,
    key: str,
    default = ...
) -> TaintSource[UserControlled]: ...

# Request body
def django.http.request.HttpRequest.body.fget(
    self
) -> TaintSource[UserControlled]: ...

# Headers
def django.http.request.HttpRequest.META.__getitem__(
    self,
    key: str
) -> TaintSource[UserControlled]: ...
```

### Cookie Sources

```python
def django.http.request.HttpRequest.COOKIES.__getitem__(
    self,
    key: str
) -> TaintSource[Cookies]: ...

def django.http.request.HttpRequest.COOKIES.get(
    self,
    key: str,
    default = ...
) -> TaintSource[Cookies]: ...
```

### File Sources

```python
def builtins.open(
    file: str,
    mode: str = ...,
    *args,
    **kwargs
) -> TaintSource[FileRead]: ...

# File content
def io.TextIOWrapper.read(
    self,
    n: int = ...
) -> TaintSource[FileRead]: ...
```

### Database Sources

```python
# Django ORM QuerySet
def django.db.models.query.QuerySet.__iter__(
    self
) -> TaintSource[DatabaseRead]: ...

def django.db.models.query.QuerySet.values(
    self,
    *fields
) -> TaintSource[DatabaseRead]: ...
```

## Defining Sinks

Sinks mark dangerous operations where tainted data causes vulnerabilities.

### SQL Injection Sinks

```python
# Raw cursor execution
def django.db.backends.utils.CursorWrapper.execute(
    self,
    sql: TaintSink[SQL],
    params = ...
): ...

# Raw SQL in ORM
def django.db.models.query.QuerySet.raw(
    self,
    raw_query: TaintSink[SQL],
    params = ...
): ...

def django.db.models.query.QuerySet.extra(
    self,
    select: TaintSink[SQL] = ...,
    where: TaintSink[SQL] = ...,
    params = ...,
    tables: TaintSink[SQL] = ...,
    order_by: TaintSink[SQL] = ...,
    select_params = ...
): ...
```

### Command Injection Sinks

```python
def os.system(
    command: TaintSink[RemoteCodeExecution]
): ...

def os.popen(
    cmd: TaintSink[RemoteCodeExecution],
    mode: str = ...,
    buffering: int = ...
): ...

def subprocess.run(
    args: TaintSink[RemoteCodeExecution],
    *other_args,
    **kwargs
): ...

def subprocess.Popen.__init__(
    self,
    args: TaintSink[RemoteCodeExecution],
    *other_args,
    **kwargs
): ...
```

### XSS Sinks

```python
def django.http.response.HttpResponse.__init__(
    self,
    content: TaintSink[XSS] = ...,
    *args,
    **kwargs
): ...

def django.shortcuts.render(
    request,
    template_name: str,
    context: TaintSink[XSS] = ...,
    *args,
    **kwargs
): ...
```

### File System Sinks

```python
def builtins.open(
    file: TaintSink[FileSystem],
    mode: str = ...,
    *args,
    **kwargs
): ...

def os.path.join(
    path: TaintSink[FileSystem],
    *paths: TaintSink[FileSystem]
) -> str: ...

def shutil.copy(
    src: TaintSink[FileSystem],
    dst: TaintSink[FileSystem]
): ...
```

### SSRF Sinks

```python
def requests.get(
    url: TaintSink[SSRF],
    *args,
    **kwargs
): ...

def requests.post(
    url: TaintSink[SSRF],
    *args,
    **kwargs
): ...

def urllib.request.urlopen(
    url: TaintSink[SSRF],
    *args,
    **kwargs
): ...
```

### Deserialization Sinks

```python
def pickle.loads(
    data: TaintSink[Deserialization]
): ...

def pickle.load(
    file: TaintSink[Deserialization]
): ...

def yaml.load(
    stream: TaintSink[Deserialization],
    Loader = ...
): ...

def yaml.unsafe_load(
    stream: TaintSink[Deserialization]
): ...
```

## Defining Sanitizers

Sanitizers mark functions that neutralize tainted data.

### Type Conversion Sanitizers

```python
# Integer conversion removes string taint for SQL
def builtins.int(
    __x: TaintInTaintOut[LocalReturn, NoTaint]
): ...

def builtins.float(
    __x: TaintInTaintOut[LocalReturn, NoTaint]
): ...

def builtins.bool(
    __x: TaintInTaintOut[LocalReturn, NoTaint]
): ...
```

### Escape Function Sanitizers

```python
# HTML escaping
def django.utils.html.escape(
    text: TaintInTaintOut[LocalReturn, NoTaint]
) -> str: ...

def markupsafe.escape(
    s: TaintInTaintOut[LocalReturn, NoTaint]
) -> str: ...

# SQL parameterization (implicit sanitizer)
def django.db.backends.utils.CursorWrapper.execute(
    self,
    sql: str,
    params: TaintInTaintOut[LocalReturn, NoTaint] = ...
): ...
```

### Validation Sanitizers

```python
# UUID validation
def uuid.UUID.__init__(
    self,
    hex: TaintInTaintOut[LocalReturn, NoTaint] = ...
): ...

# Path validation
def os.path.basename(
    path: TaintInTaintOut[LocalReturn, NoTaint]
) -> str: ...
```

## Taint Propagation

Model how taint flows through functions:

### TaintInTaintOut

Propagates taint from input to output:

```python
# Taint propagates through string operations
def str.format(
    self: TaintInTaintOut[LocalReturn],
    *args: TaintInTaintOut[LocalReturn],
    **kwargs: TaintInTaintOut[LocalReturn]
) -> str: ...

def str.__add__(
    self: TaintInTaintOut[LocalReturn],
    other: TaintInTaintOut[LocalReturn]
) -> str: ...

# Dictionary access propagates taint
def dict.__getitem__(
    self: TaintInTaintOut[LocalReturn],
    key
): ...
```

### Attribute Propagation

```python
# Accessing attributes preserves taint
AttributeModel = TaintInTaintOut[LocalReturn]

def object.__getattribute__(
    self: AttributeModel,
    name: str
): ...
```

## Advanced Model Patterns

### Conditional Sanitization

```python
# Only sanitizes for specific sink
def custom_escape(
    text: Sanitize[TaintSink[XSS]]
) -> str: ...
```

### Partial Sinks

Mark only specific parameters as sinks:

```python
def complex_function(
    safe_param: str,
    dangerous_param: TaintSink[SQL],
    another_safe: int
): ...
```

### Multiple Taint Types

```python
def get_request_data(
    request
) -> TaintSource[UserControlled, RequestData]: ...
```

### Features for Tracking

```python
def str.format(
    self: TaintInTaintOut[LocalReturn, Via[format-string]],
    *args: TaintInTaintOut[LocalReturn]
) -> str: ...
```

## VulnShop Model Examples

### Complete Django Source Model

```python
# models/django_sources.pysa

# GET parameters
def django.http.request.QueryDict.__getitem__(
    self, key: str
) -> TaintSource[UserControlled]: ...

def django.http.request.QueryDict.get(
    self, key: str, default = ...
) -> TaintSource[UserControlled]: ...

def django.http.request.QueryDict.getlist(
    self, key: str, default = ...
) -> TaintSource[UserControlled]: ...

# POST data
def django.http.request.HttpRequest.POST.__getitem__(
    self, key: str
) -> TaintSource[UserControlled]: ...

# JSON body
def json.loads(
    s: str
) -> TaintSource[UserControlled]: ...

# Path parameters (captured from URL)
# Note: These are implicitly tainted through view arguments
```

### Complete SQL Sink Model

```python
# models/django_sinks.pysa

# Direct cursor execution
def django.db.backends.utils.CursorWrapper.execute(
    self,
    sql: TaintSink[SQL],
    params = ...
): ...

def django.db.backends.utils.CursorWrapper.executemany(
    self,
    sql: TaintSink[SQL],
    param_list = ...
): ...

# Raw queries
def django.db.models.query.QuerySet.raw(
    self,
    raw_query: TaintSink[SQL],
    params = ...,
    translations = ...,
    using = ...
): ...

# Extra clauses (deprecated but still used)
def django.db.models.query.QuerySet.extra(
    self,
    select: TaintSink[SQL] = ...,
    where: TaintSink[SQL] = ...,
    params = ...,
    tables: TaintSink[SQL] = ...,
    order_by: TaintSink[SQL] = ...,
    select_params = ...
): ...
```

## Testing Models

Verify your models work correctly:

```python
# test_models.py
def test_sql_injection():
    """This should trigger rule 5001"""
    user_input = request.GET["query"]  # Source
    cursor.execute(f"SELECT * FROM users WHERE name = '{user_input}'")  # Sink

def test_sanitized_query():
    """This should NOT trigger - parameterized query"""
    user_input = request.GET["query"]  # Source
    cursor.execute("SELECT * FROM users WHERE name = %s", [user_input])  # Safe
```

Run verification:

```bash
pyre analyze --verify-models
```

## Next Steps

- [Running Pysa](running.md) - Execute analysis with your models
- [Advanced Techniques](advanced.md) - Complex patterns and optimization
- [Configuration](configuration.md) - Fine-tune Pysa settings
