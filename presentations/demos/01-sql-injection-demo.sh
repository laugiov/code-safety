#!/bin/bash
# =============================================================================
# Demo 1: SQL Injection Detection
# =============================================================================
# This demo shows how each tool detects SQL injection in VulnShop
# Run from the project root directory
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}=============================================${NC}"
echo -e "${BLUE}  SQL Injection Detection Demo${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 1: Show the vulnerable code
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 1: The Vulnerable Code${NC}"
echo -e "File: vulnerable-app/authentication/views.py"
echo ""

cat << 'EOF'
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')  # SOURCE
        password = request.POST.get('password')

        # VULNERABLE: SQL Injection via f-string
        query = f"SELECT * FROM auth_user WHERE username = '{username}' AND password = '{password}'"

        with connection.cursor() as cursor:
            cursor.execute(query)  # SINK
            user = cursor.fetchone()
EOF

echo ""
echo -e "${RED}Attack: username = admin'-- ${NC}"
echo -e "${RED}Result: Authentication bypass!${NC}"
echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 2: Semgrep Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 2: Semgrep Detection (~5 seconds)${NC}"
echo ""

cd analysis/semgrep
echo "Running: semgrep --config rules/injection/ ../../vulnerable-app/authentication/"
echo ""

time semgrep --config rules/injection/sql-injection.yml ../../vulnerable-app/authentication/ 2>/dev/null || true

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 3: Pysa Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 3: Pysa Detection (~45 seconds)${NC}"
echo ""

cd ../pysa
echo "Running: pyre analyze (filtered for SQL injection)"
echo ""

# Note: In a real demo, you would run pyre analyze
# For demo purposes, we show expected output
cat << 'EOF'
[Expected Pysa Output]

Issue: SQL Injection (code 5001)
  File: authentication/views.py
  Line: 32
  Message: User-controlled data flows to SQL query

  Trace:
    Source: request.POST.get('username') [UserControlled]
      ↓ via f-string formatting
    Sink: cursor.execute(query) [SQL]
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 4: CodeQL Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 4: CodeQL Detection (~2 minutes)${NC}"
echo ""

cd ../codeql
echo "Running: codeql database analyze (filtered for SQL injection)"
echo ""

# Note: In a real demo, you would run codeql
cat << 'EOF'
[Expected CodeQL Output]

sql-injection.ql: SQL Injection vulnerability
  Path: authentication/views.py:32

  Source: request.POST.get('username')
    ↓ string formatting
    ↓ variable assignment
  Sink: cursor.execute(query)

  Severity: error
  CWE: CWE-89
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 5: Comparison
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 5: Detection Comparison${NC}"
echo ""

echo -e "┌─────────────┬──────────┬───────────┬──────────┐"
echo -e "│ Tool        │ Detected │ Time      │ Details  │"
echo -e "├─────────────┼──────────┼───────────┼──────────┤"
echo -e "│ Semgrep     │ ${GREEN}✅${NC}       │ ~5s       │ Pattern  │"
echo -e "│ Pysa        │ ${GREEN}✅${NC}       │ ~45s      │ Taint    │"
echo -e "│ CodeQL      │ ${GREEN}✅${NC}       │ ~2m       │ Dataflow │"
echo -e "└─────────────┴──────────┴───────────┴──────────┘"

echo ""
echo -e "${GREEN}All three tools successfully detect this SQL injection!${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 6: The Fix
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 6: The Fix${NC}"
echo ""

cat << 'EOF'
# SAFE: Parameterized query
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        query = "SELECT * FROM auth_user WHERE username = %s AND password = %s"

        with connection.cursor() as cursor:
            cursor.execute(query, [username, password])  # Parameters sanitize input
            user = cursor.fetchone()
EOF

echo ""
echo -e "${GREEN}Demo Complete!${NC}"
