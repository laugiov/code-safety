---
title: VulnShop Overview
description: Overview of the VulnShop vulnerable application
---

# VulnShop Overview

VulnShop is a deliberately vulnerable Django e-commerce application designed for learning taint analysis and security testing.

## Purpose

VulnShop serves as:

1. **Learning Platform** - Study real vulnerability patterns
2. **Testing Target** - Evaluate taint analysis tools
3. **Benchmark Application** - Measure detection accuracy

## Features

### E-commerce Functionality

- User registration and authentication
- Product catalog with search
- Shopping cart
- Checkout and payment
- Order history
- Product reviews

### Vulnerability Coverage

16 deliberately implemented vulnerabilities:

| Category | Vulnerabilities |
|----------|-----------------|
| Injection | SQL Injection (2), Command Injection, XSS (2), SSTI |
| Data Exposure | Path Traversal, SSRF, XXE |
| Deserialization | Insecure Pickle |
| Access Control | IDOR, Mass Assignment |
| Configuration | Hardcoded Secrets, Sensitive Logging |

## Technology Stack

- **Framework**: Django 4.2
- **Database**: SQLite (dev) / PostgreSQL (prod)
- **Frontend**: Django Templates + Bootstrap
- **API**: Django REST Framework

## Quick Access

- **Web UI**: http://localhost:8000
- **Admin Panel**: http://localhost:8000/admin/
- **API**: http://localhost:8000/api/

## Default Accounts

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |
| john | user123 | Customer |
| jane | user123 | Customer |

## Next Steps

- [Architecture](architecture.md) - Technical details
- [Vulnerability Map](vulnerability-map.md) - All vulnerabilities
- [Exploitation Guide](exploitation.md) - Hands-on tutorials
