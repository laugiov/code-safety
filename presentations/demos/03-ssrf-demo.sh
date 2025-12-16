#!/bin/bash
# =============================================================================
# Demo 3: Server-Side Request Forgery (SSRF) Detection
# =============================================================================
# This demo shows how each tool detects SSRF vulnerabilities in VulnShop
# Run from the project root directory
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  SSRF (Server-Side Request Forgery) Demo${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 1: Show the vulnerable code
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 1: The Vulnerable Code${NC}"
echo -e "File: vulnerable-app/webhooks/views.py"
echo ""

cat << 'EOF'
def fetch_webhook_content(request):
    """Fetch content from webhook URL - VULNERABLE to SSRF"""
    if request.method == 'POST':
        url = request.POST.get('webhook_url')  # SOURCE: User input

        # VULNERABLE: No URL validation
        response = requests.get(url)  # SINK: Server makes request to user URL

        return JsonResponse({
            'status': response.status_code,
            'content': response.text[:1000]
        })
EOF

echo ""
echo -e "${RED}Attack: webhook_url = http://169.254.169.254/latest/meta-data/iam/security-credentials/${NC}"
echo -e "${RED}Result: Access to AWS instance metadata (credential theft)!${NC}"
echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 2: Attack Scenarios
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 2: SSRF Attack Scenarios${NC}"
echo ""

cat << 'EOF'
┌─────────────────────────────────────────────────────────────────────────┐
│                        SSRF Attack Targets                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Cloud Metadata Services                                              │
│     ├── AWS: http://169.254.169.254/latest/meta-data/                   │
│     ├── GCP: http://metadata.google.internal/                           │
│     ├── Azure: http://169.254.169.254/metadata/instance                 │
│     └── Digital Ocean: http://169.254.169.254/metadata/v1/              │
│                                                                          │
│  2. Internal Services                                                    │
│     ├── http://localhost:6379/ (Redis)                                  │
│     ├── http://127.0.0.1:9200/ (Elasticsearch)                          │
│     └── http://internal-api.company.local/admin                         │
│                                                                          │
│  3. Local File Access (via file://)                                     │
│     └── file:///etc/passwd                                              │
│                                                                          │
│  4. Port Scanning                                                        │
│     └── http://internal-host:PORT/ (enumerate open ports)               │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 3: Semgrep Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 3: Semgrep Detection (~5 seconds)${NC}"
echo ""

cd analysis/semgrep
echo "Running: semgrep --config rules/ssrf/"
echo ""

time semgrep --config rules/ssrf/ ../../vulnerable-app/webhooks/ 2>/dev/null || true

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 4: Pysa Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 4: Pysa Detection${NC}"
echo ""

cd ../pysa
echo "Running: pyre analyze (filtered for SSRF)"
echo ""

cat << 'EOF'
[Expected Pysa Output]

Issue: Server-Side Request Forgery (code 5003)
  File: webhooks/views.py
  Line: 24
  Message: User-controlled URL flows to HTTP request

  Trace:
    Source: request.POST.get('webhook_url') [UserControlled]
      ↓ variable assignment
    Sink: requests.get(url) [SSRF]

  Additional traces found:
    - webhooks/views.py:45 (verify_webhook)
    - notifications/views.py:67 (send_notification)
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 5: CodeQL Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 5: CodeQL Detection${NC}"
echo ""

cd ../codeql
echo "Running: codeql database analyze --queries=ssrf.ql"
echo ""

cat << 'EOF'
[Expected CodeQL Output]

ssrf.ql: Server-Side Request Forgery
  Path: webhooks/views.py:24

  Source: request.POST.get('webhook_url')
    ↓ local variable
  Sink: requests.get(url)

  Severity: error
  CWE: CWE-918 (Server-Side Request Forgery)

  Additional findings:
  - Full SSRF in webhooks/views.py (3 locations)
  - Partial SSRF in notifications/views.py (URL path controlled)
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 6: SSRF Bypass Techniques
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 6: Common SSRF Bypass Techniques${NC}"
echo ""

cat << 'EOF'
Bypass Techniques (for security testing):

1. IP Address Obfuscation:
   - Decimal: http://2130706433/ (127.0.0.1)
   - Octal: http://0177.0.0.1/
   - Hex: http://0x7f.0x0.0x0.0x1/

2. DNS Rebinding:
   - Use domain that resolves to internal IP after TTL expires
   - Tools: singularity, rbndr

3. URL Parser Confusion:
   - http://localhost#@evil.com/
   - http://evil.com@localhost/
   - http://localhost%00@evil.com/

4. Protocol Smuggling:
   - gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall
   - dict://localhost:6379/info

5. Redirect Chains:
   - External URL redirects to internal address
   - Open redirect → SSRF escalation
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 7: Comparison
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 7: Detection Comparison${NC}"
echo ""

echo -e "┌─────────────┬──────────┬───────────┬────────────────────┐"
echo -e "│ Tool        │ Detected │ Bypasses  │ Notes              │"
echo -e "├─────────────┼──────────┼───────────┼────────────────────┤"
echo -e "│ Semgrep     │ ${GREEN}✅${NC}       │ ⚠️ Some   │ Pattern-based      │"
echo -e "│ Pysa        │ ${GREEN}✅${NC}       │ ${GREEN}✅${NC} Most  │ Tracks all flows   │"
echo -e "│ CodeQL      │ ${GREEN}✅${NC}       │ ${GREEN}✅${NC} Most  │ Full/Partial SSRF  │"
echo -e "└─────────────┴──────────┴───────────┴────────────────────┘"

echo ""
echo -e "${CYAN}Note: CodeQL distinguishes between Full SSRF (entire URL controlled)${NC}"
echo -e "${CYAN}      and Partial SSRF (only path/parameters controlled)${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 8: The Fix
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 8: The Fix${NC}"
echo ""

cat << 'EOF'
# SAFE: URL validation with allowlist
from urllib.parse import urlparse
import ipaddress

ALLOWED_SCHEMES = {'http', 'https'}
BLOCKED_HOSTS = {
    'localhost', '127.0.0.1', '0.0.0.0',
    '169.254.169.254',  # AWS metadata
    'metadata.google.internal',  # GCP metadata
}

def is_safe_url(url):
    """Validate URL is safe for server-side requests"""
    try:
        parsed = urlparse(url)

        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            return False

        # Check for blocked hosts
        hostname = parsed.hostname.lower()
        if hostname in BLOCKED_HOSTS:
            return False

        # Check for private IP ranges
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass  # Not an IP address

        return True
    except Exception:
        return False

def fetch_webhook_content(request):
    if request.method == 'POST':
        url = request.POST.get('webhook_url')

        if not is_safe_url(url):
            return JsonResponse({'error': 'Invalid URL'}, status=400)

        # Additional: Use timeout and disable redirects
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=False,
            headers={'User-Agent': 'WebhookFetcher/1.0'}
        )
        return JsonResponse({'content': response.text[:1000]})
EOF

echo ""
echo -e "${GREEN}Demo Complete!${NC}"
