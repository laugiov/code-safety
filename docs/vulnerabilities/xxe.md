---
title: XML External Entity (XXE)
description: Understanding and detecting XXE vulnerabilities
---

# XML External Entity (XXE)

**XXE** attacks exploit XML parsers that process external entity references. This can lead to file disclosure, SSRF, denial of service, or even remote code execution.

## Overview

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-611: XXE](https://cwe.mitre.org/data/definitions/611.html) |
| **OWASP** | A05:2021 - Security Misconfiguration |
| **Severity** | High (CVSS 7.5-9.0) |
| **Impact** | File disclosure, SSRF, DoS |

## How It Works

**Malicious XML:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

When parsed, `&xxe;` is replaced with contents of `/etc/passwd`.

## VulnShop Implementation

**File:** `api/views.py:50-70`

```python
from xml.etree import ElementTree as ET

def import_products(request):
    xml_data = request.body

    # VULNERABLE: External entity processing enabled
    tree = ET.parse(io.BytesIO(xml_data))
    root = tree.getroot()

    for product in root.findall('product'):
        name = product.find('name').text
        price = product.find('price').text
        Product.objects.create(name=name, price=price)

    return JsonResponse({'status': 'imported'})
```

**Exploit:**
```xml
<?xml version="1.0"?>
<!DOCTYPE products [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<products>
  <product>
    <name>&xxe;</name>
    <price>0</price>
  </product>
</products>
```

## Detection

### Semgrep

```yaml
rules:
  - id: xxe-vulnerable-parser
    pattern-either:
      - pattern: xml.etree.ElementTree.parse(...)
      - pattern: xml.dom.minidom.parse(...)
      - pattern: lxml.etree.parse(...)
    message: >
      XML parser may be vulnerable to XXE.
      Use defusedxml or disable external entities.
    severity: ERROR
    languages: [python]
```

## Remediation

### 1. Use defusedxml (Recommended)

```python
import defusedxml.ElementTree as ET

def import_products(request):
    xml_data = request.body

    # SAFE: defusedxml prevents XXE
    tree = ET.parse(io.BytesIO(xml_data))
    root = tree.getroot()

    for product in root.findall('product'):
        name = product.find('name').text
        price = product.find('price').text
        Product.objects.create(name=name, price=price)

    return JsonResponse({'status': 'imported'})
```

### 2. Disable External Entities (lxml)

```python
from lxml import etree

parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False
)

tree = etree.parse(io.BytesIO(xml_data), parser)
```

### 3. Use JSON Instead

```python
import json

def import_products(request):
    # SAFE: JSON doesn't have entity expansion
    data = json.loads(request.body)

    for product in data['products']:
        Product.objects.create(
            name=product['name'],
            price=product['price']
        )

    return JsonResponse({'status': 'imported'})
```

## XXE Payloads

### File Disclosure

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

### SSRF

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]>
```

### Billion Laughs (DoS)

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!-- ... continues exponentially -->
]>
<lolz>&lol9;</lolz>
```

## References

- [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [CWE-611](https://cwe.mitre.org/data/definitions/611.html)
- [defusedxml library](https://github.com/tiran/defusedxml)
