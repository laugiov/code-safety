#!/bin/bash
# =============================================================================
# Setup Script - Taint Analysis Masterclass
# =============================================================================
# Automated setup for the development environment.
#
# Usage:
#   ./scripts/setup.sh           # Full setup
#   ./scripts/setup.sh --quick   # Quick setup (skip optional tools)
#   ./scripts/setup.sh --docker  # Docker-only setup

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Header
echo ""
echo "=============================================="
echo "  Taint Analysis Masterclass - Setup Script"
echo "=============================================="
echo ""

# Parse arguments
QUICK_MODE=false
DOCKER_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --docker)
            DOCKER_ONLY=true
            shift
            ;;
        *)
            warning "Unknown option: $1"
            shift
            ;;
    esac
done

# =============================================================================
# Check Prerequisites
# =============================================================================
info "Checking prerequisites..."

check_command() {
    if command -v "$1" &> /dev/null; then
        success "$1 is installed"
        return 0
    else
        error "$1 is not installed"
        return 1
    fi
}

# Required tools
MISSING_REQUIRED=false

if ! check_command "python3"; then
    MISSING_REQUIRED=true
fi

if ! check_command "pip3"; then
    MISSING_REQUIRED=true
fi

if ! check_command "git"; then
    MISSING_REQUIRED=true
fi

if ! check_command "docker"; then
    warning "Docker is not installed (optional for local development)"
fi

if ! check_command "docker-compose"; then
    warning "Docker Compose is not installed (optional for local development)"
fi

if [ "$MISSING_REQUIRED" = true ]; then
    error "Missing required tools. Please install them and try again."
    exit 1
fi

# =============================================================================
# Docker-only Setup
# =============================================================================
if [ "$DOCKER_ONLY" = true ]; then
    info "Running Docker-only setup..."

    if ! command -v docker &> /dev/null; then
        error "Docker is required for --docker mode"
        exit 1
    fi

    info "Building Docker images..."
    docker-compose build

    info "Starting services..."
    docker-compose up -d vulnshop docs

    success "Docker setup complete!"
    echo ""
    echo "Services are running:"
    echo "  - VulnShop: http://localhost:8000"
    echo "  - Documentation: http://localhost:8080"
    echo ""
    echo "Run 'docker-compose down' to stop services."
    exit 0
fi

# =============================================================================
# Python Environment
# =============================================================================
info "Setting up Python environment..."

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
REQUIRED_VERSION="3.11"

if [[ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]]; then
    error "Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)"
    exit 1
fi

success "Python $PYTHON_VERSION detected"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    info "Creating virtual environment..."
    python3 -m venv venv
    success "Virtual environment created"
else
    info "Virtual environment already exists"
fi

# Activate virtual environment
info "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
info "Upgrading pip..."
pip install --upgrade pip

# =============================================================================
# Install Dependencies
# =============================================================================
info "Installing dependencies..."

# Install development dependencies
pip install -r requirements-dev.txt

# Install VulnShop dependencies (may have warnings due to vulnerable packages)
info "Installing VulnShop dependencies..."
pip install -r vulnerable-app/requirements.txt 2>/dev/null || warning "Some VulnShop dependencies may have vulnerabilities (expected)"

success "Dependencies installed"

# =============================================================================
# Install Analysis Tools (if not quick mode)
# =============================================================================
if [ "$QUICK_MODE" = false ]; then
    info "Installing analysis tools..."

    # Pyre/Pysa
    if ! command -v pyre &> /dev/null; then
        info "Installing Pyre/Pysa..."
        pip install pyre-check
    else
        success "Pyre/Pysa already installed"
    fi

    # Semgrep
    if ! command -v semgrep &> /dev/null; then
        info "Installing Semgrep..."
        pip install semgrep
    else
        success "Semgrep already installed"
    fi

    # CodeQL (manual installation required)
    if ! command -v codeql &> /dev/null; then
        warning "CodeQL CLI is not installed"
        echo "  To install CodeQL:"
        echo "  1. Download from: https://github.com/github/codeql-cli-binaries/releases"
        echo "  2. Extract and add to PATH"
        echo "  3. Run: codeql pack download codeql/python-queries"
    else
        success "CodeQL already installed"
    fi
fi

# =============================================================================
# Setup Pre-commit Hooks
# =============================================================================
info "Setting up pre-commit hooks..."

if command -v pre-commit &> /dev/null; then
    pre-commit install
    success "Pre-commit hooks installed"
else
    warning "pre-commit not found, skipping hooks setup"
fi

# =============================================================================
# Initialize Database (if running locally)
# =============================================================================
if [ -f "vulnerable-app/manage.py" ]; then
    info "Setting up VulnShop database..."
    cd vulnerable-app
    python manage.py migrate --run-syncdb 2>/dev/null || warning "Database migration had issues (may be expected)"
    cd ..
    success "Database initialized"
fi

# =============================================================================
# Docker Setup (if available)
# =============================================================================
if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
    info "Building Docker images..."
    docker-compose build
    success "Docker images built"
else
    warning "Docker not available, skipping Docker setup"
fi

# =============================================================================
# Final Summary
# =============================================================================
echo ""
echo "=============================================="
echo "           Setup Complete!"
echo "=============================================="
echo ""
success "Taint Analysis Masterclass is ready!"
echo ""
echo "Next steps:"
echo ""
echo "  1. Activate the virtual environment:"
echo "     ${BLUE}source venv/bin/activate${NC}"
echo ""
echo "  2. Start VulnShop:"
echo "     ${BLUE}make docker-up${NC}  (Docker)"
echo "     ${BLUE}make run${NC}        (Local)"
echo ""
echo "  3. Run analysis:"
echo "     ${BLUE}make analyze-all${NC}"
echo ""
echo "  4. View documentation:"
echo "     ${BLUE}make docs-serve${NC}"
echo "     Then open: http://localhost:8000"
echo ""
echo "For more commands, run: ${BLUE}make help${NC}"
echo ""
