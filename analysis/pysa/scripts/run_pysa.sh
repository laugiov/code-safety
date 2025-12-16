#!/bin/bash
# ==============================================================================
# Pysa Analysis Runner Script
# ==============================================================================
#
# This script orchestrates the Pysa taint analysis for VulnShop.
# It handles model generation, type checking, taint analysis, and result conversion.
#
# Usage:
#   ./run_pysa.sh [OPTIONS]
#
# Options:
#   --skip-type-check    Skip Pyre type checking phase
#   --skip-model-gen     Skip model generation phase
#   --verbose            Enable verbose output
#   --json-only          Only output JSON results (no SARIF conversion)
#   --help               Show this help message
#
# Requirements:
#   - Python 3.8+
#   - pyre-check (pip install pyre-check)
#   - Django and app dependencies installed
#
# ==============================================================================

set -e  # Exit on error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYSA_DIR="$(dirname "$SCRIPT_DIR")"
APP_DIR="$PYSA_DIR/../../vulnerable-app"
RESULTS_DIR="$PYSA_DIR/results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
SKIP_TYPE_CHECK=false
SKIP_MODEL_GEN=false
VERBOSE=false
JSON_ONLY=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-type-check)
            SKIP_TYPE_CHECK=true
            shift
            ;;
        --skip-model-gen)
            SKIP_MODEL_GEN=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --json-only)
            JSON_ONLY=true
            shift
            ;;
        --help)
            head -30 "$0" | tail -25
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo ""
    echo -e "${GREEN}=== $1 ===${NC}"
}

# Check prerequisites
check_prerequisites() {
    log_step "Checking Prerequisites"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    log_info "Python: $(python3 --version)"

    # Check Pyre
    if ! command -v pyre &> /dev/null; then
        log_error "Pyre is not installed. Install with: pip install pyre-check"
        exit 1
    fi
    log_info "Pyre: $(pyre --version 2>&1 | head -1)"

    # Check if app directory exists
    if [[ ! -d "$APP_DIR" ]]; then
        log_error "VulnShop application not found at: $APP_DIR"
        exit 1
    fi
    log_info "Application directory: $APP_DIR"

    # Check if taint.config exists
    if [[ ! -f "$PYSA_DIR/taint.config" ]]; then
        log_error "Taint configuration not found: $PYSA_DIR/taint.config"
        exit 1
    fi
    log_info "Taint config: $PYSA_DIR/taint.config"

    log_success "Prerequisites check passed"
}

# Create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results directory: $RESULTS_DIR"
}

# Generate models
generate_models() {
    if [[ "$SKIP_MODEL_GEN" == true ]]; then
        log_warning "Skipping model generation (--skip-model-gen)"
        return 0
    fi

    log_step "Generating Pysa Models"

    cd "$PYSA_DIR"

    # Run model generator
    if [[ "$VERBOSE" == true ]]; then
        python3 model_generators/generate_django_models.py
    else
        python3 model_generators/generate_django_models.py 2>&1 | tail -10
    fi

    if [[ -f "models/vulnshop_auto.pysa" ]]; then
        log_success "Models generated: models/vulnshop_auto.pysa"
        log_info "$(wc -l < models/vulnshop_auto.pysa) lines generated"
    else
        log_warning "Model generation may have failed"
    fi
}

# Run Pyre type check
run_type_check() {
    if [[ "$SKIP_TYPE_CHECK" == true ]]; then
        log_warning "Skipping type check (--skip-type-check)"
        return 0
    fi

    log_step "Running Pyre Type Check"

    cd "$PYSA_DIR"

    # Run Pyre check (non-blocking - we continue even with type errors)
    if [[ "$VERBOSE" == true ]]; then
        pyre check --noninteractive 2>&1 | tee "$RESULTS_DIR/pyre_check.log" || true
    else
        pyre check --noninteractive > "$RESULTS_DIR/pyre_check.log" 2>&1 || true
    fi

    # Count errors
    ERROR_COUNT=$(grep -c "Error" "$RESULTS_DIR/pyre_check.log" 2>/dev/null || echo "0")
    log_info "Type errors found: $ERROR_COUNT (non-blocking)"
}

# Run Pysa analysis
run_pysa_analysis() {
    log_step "Running Pysa Taint Analysis"

    cd "$PYSA_DIR"

    # Create analysis timestamp
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

    # Run Pysa
    log_info "Starting taint analysis..."
    START_TIME=$(date +%s)

    if [[ "$VERBOSE" == true ]]; then
        pyre analyze \
            --save-results-to "$RESULTS_DIR/pysa_results.json" \
            --no-verify \
            2>&1 | tee "$RESULTS_DIR/pysa_output.log"
    else
        pyre analyze \
            --save-results-to "$RESULTS_DIR/pysa_results.json" \
            --no-verify \
            > "$RESULTS_DIR/pysa_output.log" 2>&1
    fi

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    log_info "Analysis completed in ${DURATION}s"

    # Check if results were generated
    if [[ -f "$RESULTS_DIR/pysa_results.json" ]]; then
        log_success "Results saved to: $RESULTS_DIR/pysa_results.json"

        # Count findings
        if command -v jq &> /dev/null; then
            FINDING_COUNT=$(jq 'length' "$RESULTS_DIR/pysa_results.json" 2>/dev/null || echo "0")
            log_info "Total findings: $FINDING_COUNT"
        fi
    else
        log_error "No results file generated"
        return 1
    fi
}

# Convert results to SARIF
convert_to_sarif() {
    if [[ "$JSON_ONLY" == true ]]; then
        log_warning "Skipping SARIF conversion (--json-only)"
        return 0
    fi

    log_step "Converting to SARIF Format"

    cd "$PYSA_DIR"

    if [[ ! -f "$RESULTS_DIR/pysa_results.json" ]]; then
        log_error "No JSON results to convert"
        return 1
    fi

    # Run SARIF converter
    python3 scripts/parse_results.py \
        --input "$RESULTS_DIR/pysa_results.json" \
        --output "$RESULTS_DIR/pysa_results.sarif"

    if [[ -f "$RESULTS_DIR/pysa_results.sarif" ]]; then
        log_success "SARIF results saved to: $RESULTS_DIR/pysa_results.sarif"
    else
        log_warning "SARIF conversion may have failed"
    fi
}

# Print summary
print_summary() {
    log_step "Analysis Summary"

    echo ""
    echo "Results Directory: $RESULTS_DIR"
    echo ""
    echo "Generated Files:"
    ls -la "$RESULTS_DIR"/*.{json,sarif,log} 2>/dev/null | awk '{print "  " $NF ": " $5 " bytes"}'

    if [[ -f "$RESULTS_DIR/pysa_results.json" ]] && command -v jq &> /dev/null; then
        echo ""
        echo "Findings by Rule:"
        jq -r '.[].code // "unknown" | tostring' "$RESULTS_DIR/pysa_results.json" 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | \
            while read count code; do
                echo "  Rule $code: $count findings"
            done
    fi

    echo ""
    log_success "Pysa analysis complete!"
}

# Main execution
main() {
    echo ""
    echo "============================================================"
    echo "       PYSA TAINT ANALYSIS FOR VULNSHOP"
    echo "============================================================"
    echo ""

    check_prerequisites
    setup_results_dir
    generate_models
    run_type_check
    run_pysa_analysis
    convert_to_sarif
    print_summary
}

# Run main
main
