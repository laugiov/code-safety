#!/bin/bash
# ==============================================================================
# Semgrep Analysis Runner Script
# ==============================================================================
#
# This script runs Semgrep analysis on the VulnShop application using
# custom rules and community rulesets.
#
# Usage:
#   ./run_semgrep.sh [OPTIONS]
#
# Options:
#   --rules-only         Use only custom rules (no community rules)
#   --include-community  Include p/python, p/django, p/owasp-top-ten
#   --output-format      Output format (sarif|json|text) [default: sarif]
#   --severity           Minimum severity (INFO|WARNING|ERROR) [default: WARNING]
#   --verbose            Enable verbose output
#   --help               Show this help message
#
# Requirements:
#   - Semgrep CLI installed (pip install semgrep)
#
# ==============================================================================

set -e  # Exit on error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEMGREP_DIR="$(dirname "$SCRIPT_DIR")"
APP_DIR="$SEMGREP_DIR/../../vulnerable-app"
RESULTS_DIR="$SEMGREP_DIR/results"
RULES_DIR="$SEMGREP_DIR/rules"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
RULES_ONLY=false
INCLUDE_COMMUNITY=true
OUTPUT_FORMAT="sarif"
MIN_SEVERITY="WARNING"
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --rules-only)
            RULES_ONLY=true
            INCLUDE_COMMUNITY=false
            shift
            ;;
        --include-community)
            INCLUDE_COMMUNITY=true
            shift
            ;;
        --output-format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --severity)
            MIN_SEVERITY="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            head -28 "$0" | tail -23
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

    # Check Semgrep CLI
    if ! command -v semgrep &> /dev/null; then
        log_error "Semgrep CLI is not installed"
        echo "Install with: pip install semgrep"
        exit 1
    fi
    log_info "Semgrep: $(semgrep --version 2>/dev/null | head -1)"

    # Check if app directory exists
    if [[ ! -d "$APP_DIR" ]]; then
        log_error "VulnShop application not found at: $APP_DIR"
        exit 1
    fi
    log_info "Application directory: $APP_DIR"

    # Check if rules directory exists
    if [[ ! -d "$RULES_DIR" ]]; then
        log_error "Rules directory not found at: $RULES_DIR"
        exit 1
    fi
    log_info "Rules directory: $RULES_DIR"

    # Count rules
    RULE_COUNT=$(find "$RULES_DIR" -name "*.yml" -o -name "*.yaml" | wc -l)
    log_info "Custom rules found: $RULE_COUNT"

    log_success "Prerequisites check passed"
}

# Create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results directory: $RESULTS_DIR"
}

# Build config arguments
build_config_args() {
    CONFIG_ARGS="--config $RULES_DIR"

    if [[ "$INCLUDE_COMMUNITY" == true ]]; then
        CONFIG_ARGS="$CONFIG_ARGS --config p/python"
        CONFIG_ARGS="$CONFIG_ARGS --config p/django"
        CONFIG_ARGS="$CONFIG_ARGS --config p/owasp-top-ten"
        CONFIG_ARGS="$CONFIG_ARGS --config p/security-audit"
    fi

    echo "$CONFIG_ARGS"
}

# Run Semgrep analysis
run_analysis() {
    log_step "Running Semgrep Analysis"

    CONFIG_ARGS=$(build_config_args)

    # Determine output file based on format
    case $OUTPUT_FORMAT in
        sarif)
            OUTPUT_FILE="$RESULTS_DIR/semgrep_results.sarif"
            OUTPUT_FLAG="--sarif --output=$OUTPUT_FILE"
            ;;
        json)
            OUTPUT_FILE="$RESULTS_DIR/semgrep_results.json"
            OUTPUT_FLAG="--json --output=$OUTPUT_FILE"
            ;;
        text)
            OUTPUT_FILE="$RESULTS_DIR/semgrep_results.txt"
            OUTPUT_FLAG="--text --output=$OUTPUT_FILE"
            ;;
        *)
            log_error "Invalid output format: $OUTPUT_FORMAT"
            exit 1
            ;;
    esac

    log_info "Configuration: $CONFIG_ARGS"
    log_info "Output format: $OUTPUT_FORMAT"
    log_info "Minimum severity: $MIN_SEVERITY"

    START_TIME=$(date +%s)

    # Build exclude patterns
    EXCLUDE_ARGS="--exclude '**/migrations/**' --exclude '**/tests/**' --exclude '**/__pycache__/**' --exclude '**/venv/**' --exclude '**/fixtures/**'"

    # Run Semgrep
    if [[ "$VERBOSE" == true ]]; then
        semgrep scan \
            $CONFIG_ARGS \
            $OUTPUT_FLAG \
            --severity=$MIN_SEVERITY \
            $EXCLUDE_ARGS \
            --verbose \
            "$APP_DIR" 2>&1 | tee "$RESULTS_DIR/semgrep_output.log"
    else
        semgrep scan \
            $CONFIG_ARGS \
            $OUTPUT_FLAG \
            --severity=$MIN_SEVERITY \
            $EXCLUDE_ARGS \
            "$APP_DIR" > "$RESULTS_DIR/semgrep_output.log" 2>&1
    fi

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    log_info "Analysis completed in ${DURATION}s"

    if [[ -f "$OUTPUT_FILE" ]]; then
        log_success "Results saved to: $OUTPUT_FILE"
    else
        log_warning "No results file generated"
    fi

    # Also generate JSON for summary if using SARIF
    if [[ "$OUTPUT_FORMAT" == "sarif" ]]; then
        log_info "Generating JSON summary..."
        semgrep scan \
            $CONFIG_ARGS \
            --json \
            --output="$RESULTS_DIR/semgrep_results.json" \
            --severity=$MIN_SEVERITY \
            $EXCLUDE_ARGS \
            "$APP_DIR" > /dev/null 2>&1 || true
    fi
}

# Print summary
print_summary() {
    log_step "Analysis Summary"

    echo ""
    echo "Results Directory: $RESULTS_DIR"
    echo ""
    echo "Generated Files:"
    ls -la "$RESULTS_DIR"/*.{sarif,json,txt,log} 2>/dev/null | awk '{print "  " $NF ": " $5 " bytes"}' || true

    # Parse JSON for summary if available
    if [[ -f "$RESULTS_DIR/semgrep_results.json" ]] && command -v jq &> /dev/null; then
        echo ""
        echo "Findings Summary:"

        TOTAL=$(jq '.results | length' "$RESULTS_DIR/semgrep_results.json" 2>/dev/null || echo "0")
        echo "  Total findings: $TOTAL"

        if [[ "$TOTAL" -gt 0 ]]; then
            echo ""
            echo "  By Severity:"
            jq -r '[.results[].extra.severity] | group_by(.) | map({severity: .[0], count: length}) | .[] | "    \(.severity): \(.count)"' \
                "$RESULTS_DIR/semgrep_results.json" 2>/dev/null || true

            echo ""
            echo "  Top Rules:"
            jq -r '[.results[].check_id] | group_by(.) | map({rule: .[0], count: length}) | sort_by(-.count) | .[:10][] | "    \(.rule): \(.count)"' \
                "$RESULTS_DIR/semgrep_results.json" 2>/dev/null || true
        fi
    fi

    echo ""
    log_success "Semgrep analysis complete!"
}

# Main execution
main() {
    echo ""
    echo "============================================================"
    echo "       SEMGREP ANALYSIS FOR VULNSHOP"
    echo "============================================================"
    echo ""

    check_prerequisites
    setup_results_dir
    run_analysis
    print_summary
}

# Run main
main
