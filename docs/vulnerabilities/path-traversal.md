---
title: Path Traversal
description: Understanding and detecting path traversal vulnerabilities
---

# Path Traversal

**Path Traversal** (also known as Directory Traversal) allows attackers to access files and directories outside the intended directory by manipulating file paths with sequences like `../`.

## Overview

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html) |
| **OWASP** | A01:2021 - Broken Access Control |
| **Severity** | High (CVSS 7.5) |
| **Impact** | File disclosure, potential RCE |

## How It Works

```python
# VULNERABLE: User controls file path
def download_file(request):
    filename = request.GET['file']
    filepath = f"/var/www/uploads/{filename}"
    return FileResponse(open(filepath, 'rb'))
```

**Attack:**
```
GET /download?file=../../../etc/passwd
```

**Resulting path:**
```
/var/www/uploads/../../../etc/passwd → /etc/passwd
```

## VulnShop Implementation

**File:** `catalog/views.py:85-100`

```python
def download_product_image(request, product_id):
    filename = request.GET.get('filename')

    # VULNERABLE: Path traversal
    filepath = os.path.join(settings.MEDIA_ROOT, 'products', filename)

    if os.path.exists(filepath):
        return FileResponse(open(filepath, 'rb'))
    return HttpResponse("File not found", status=404)
```

**Exploit:**
```bash
curl "http://localhost:8000/catalog/1/image/?filename=../../../../../../etc/passwd"
```

## Detection

### Pysa

```python
def builtins.open(
    file: TaintSink[FileSystem],
    mode = ...,
): ...

def os.path.join(
    path: TaintSink[FileSystem],
    *paths: TaintSink[FileSystem]
) -> str: ...
```

### Semgrep

```yaml
rules:
  - id: path-traversal
    mode: taint
    pattern-sources:
      - pattern: request.GET[...]
    pattern-sinks:
      - pattern: open($PATH, ...)
        focus-metavariable: $PATH
    pattern-sanitizers:
      - pattern: os.path.basename(...)
    message: Path traversal vulnerability
    severity: ERROR
    languages: [python]
```

## Remediation

### 1. Use basename

```python
import os

def download_file(request):
    filename = request.GET['file']

    # SAFE: Strip path components
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(settings.MEDIA_ROOT, 'products', safe_filename)

    if os.path.exists(filepath):
        return FileResponse(open(filepath, 'rb'))
    return HttpResponse("File not found", status=404)
```

### 2. Validate Path Stays Within Directory

```python
def download_file(request):
    filename = request.GET['file']
    base_dir = os.path.abspath(settings.MEDIA_ROOT)
    filepath = os.path.abspath(os.path.join(base_dir, 'products', filename))

    # SAFE: Verify path is within allowed directory
    if not filepath.startswith(base_dir):
        return HttpResponse("Access denied", status=403)

    if os.path.exists(filepath):
        return FileResponse(open(filepath, 'rb'))
    return HttpResponse("File not found", status=404)
```

### 3. Use Allowlist

```python
ALLOWED_FILES = {
    'manual.pdf': 'products/manual.pdf',
    'warranty.pdf': 'products/warranty.pdf',
}

def download_file(request):
    file_id = request.GET['file']

    if file_id not in ALLOWED_FILES:
        return HttpResponse("File not found", status=404)

    filepath = os.path.join(settings.MEDIA_ROOT, ALLOWED_FILES[file_id])
    return FileResponse(open(filepath, 'rb'))
```

## Bypass Techniques

| Technique | Payload |
|-----------|---------|
| Basic | `../../../etc/passwd` |
| URL encoded | `%2e%2e%2f%2e%2e%2fetc/passwd` |
| Double URL | `%252e%252e%252f` |
| Null byte | `../../../etc/passwd%00.jpg` |
| UNC paths (Windows) | `\\server\share\file` |

## References

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
