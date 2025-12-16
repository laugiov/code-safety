#!/bin/bash
# ==============================================================================
# CodeQL Analysis Runner Script
# ==============================================================================
#
# This script orchestrates CodeQL analysis for VulnShop.
# It handles database creation, query execution, and result formatting.
#
# Usage:
#   ./run_analysis.sh [OPTIONS]
#
# Options:
#   --suite <name>       Query suite to use (security|full) [default: security]
#   --skip-db-creation   Skip database creation (use existing)
#   --output-format      Output format (sarif|csv|json) [default: sarif]
#   --verbose            Enable verbose output
#   --help               Show this help message
#
# Requirements:
#   - CodeQL CLI installed and in PATH
#   - Python 3.8+ for source code
#
# ==============================================================================

set -e  # Exit on error

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CODEQL_DIR="$(dirname "$SCRIPT_DIR")"
APP_DIR="$CODEQL_DIR/../../vulnerable-app"
RESULTS_DIR="$CODEQL_DIR/results"
DB_DIR="$CODEQL_DIR/vulnshop-db"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
SUITE="security"
SKIP_DB_CREATION=false
OUTPUT_FORMAT="sarif"
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --suite)
            SUITE="$2"
            shift 2
            ;;
        --skip-db-creation)
            SKIP_DB_CREATION=true
            shift
            ;;
        --output-format)
            OUTPUT_FORMAT="$2"
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

    # Check CodeQL CLI
    if ! command -v codeql &> /dev/null; then
        log_error "CodeQL CLI is not installed or not in PATH"
        echo "Download from: https://github.com/github/codeql-cli-binaries/releases"
        exit 1
    fi
    log_info "CodeQL: $(codeql version --format=terse 2>/dev/null || echo 'version unknown')"

    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
        exit 1
    fi
    log_info "Python: $(python3 --version)"

    # Check if app directory exists
    if [[ ! -d "$APP_DIR" ]]; then
        log_error "VulnShop application not found at: $APP_DIR"
        exit 1
    fi
    log_info "Application directory: $APP_DIR"

    # Validate suite option
    if [[ "$SUITE" != "security" && "$SUITE" != "full" ]]; then
        log_error "Invalid suite: $SUITE. Use 'security' or 'full'"
        exit 1
    fi
    log_info "Query suite: $SUITE"

    log_success "Prerequisites check passed"
}

# Create results directory
setup_results_dir() {
    mkdir -p "$RESULTS_DIR"
    log_info "Results directory: $RESULTS_DIR"
}

# Create CodeQL database
create_database() {
    if [[ "$SKIP_DB_CREATION" == true ]]; then
        if [[ -d "$DB_DIR" ]]; then
            log_warning "Using existing database (--skip-db-creation)"
            return 0
        else
            log_error "No existing database found at $DB_DIR"
            exit 1
        fi
    fi

    log_step "Creating CodeQL Database"

    # Remove existing database
    if [[ -d "$DB_DIR" ]]; then
        log_info "Removing existing database..."
        rm -rf "$DB_DIR"
    fi

    # Create database
    log_info "Creating database from source code..."
    START_TIME=$(date +%s)

    if [[ "$VERBOSE" == true ]]; then
        codeql database create "$DB_DIR" \
            --language=python \
            --source-root="$APP_DIR" \
            --overwrite \
            2>&1 | tee "$RESULTS_DIR/db_creation.log"
    else
        codeql database create "$DB_DIR" \
            --language=python \
            --source-root="$APP_DIR" \
            --overwrite \
            > "$RESULTS_DIR/db_creation.log" 2>&1
    fi

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    log_success "Database created in ${DURATION}s"
}

# Run CodeQL analysis
run_analysis() {
    log_step "Running CodeQL Analysis"

    SUITE_FILE="$CODEQL_DIR/suites/vulnshop-${SUITE}.qls"
    QUERIES_DIR="$CODEQL_DIR/queries"

    if [[ ! -f "$SUITE_FILE" ]]; then
        log_warning "Suite file not found: $SUITE_FILE"
        log_info "Running queries from: $QUERIES_DIR"
        QUERY_PATH="$QUERIES_DIR"
    else
        log_info "Using suite: $SUITE_FILE"
        QUERY_PATH="$SUITE_FILE"
    fi

    # Determine output file based on format
    case $OUTPUT_FORMAT in
        sarif)
            OUTPUT_FILE="$RESULTS_DIR/codeql_results.sarif"
            FORMAT_FLAG="--format=sarif-latest"
            ;;
        csv)
            OUTPUT_FILE="$RESULTS_DIR/codeql_results.csv"
            FORMAT_FLAG="--format=csv"
            ;;
        json)
            OUTPUT_FILE="$RESULTS_DIR/codeql_results.json"
            FORMAT_FLAG="--format=json"
            ;;
        *)
            log_error "Invalid output format: $OUTPUT_FORMAT"
            exit 1
            ;;
    esac

    log_info "Running analysis..."
    START_TIME=$(date +%s)

    if [[ "$VERBOSE" == true ]]; then
        codeql database analyze "$DB_DIR" \
            "$QUERIES_DIR" \
            $FORMAT_FLAG \
            --output="$OUTPUT_FILE" \
            --threads=4 \
            2>&1 | tee "$RESULTS_DIR/analysis.log"
    else
        codeql database analyze "$DB_DIR" \
            "$QUERIES_DIR" \
            $FORMAT_FLAG \
            --output="$OUTPUT_FILE" \
            --threads=4 \
            > "$RESULTS_DIR/analysis.log" 2>&1
    fi

    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))

    log_info "Analysis completed in ${DURATION}s"

    if [[ -f "$OUTPUT_FILE" ]]; then
        log_success "Results saved to: $OUTPUT_FILE"
    else
        log_error "No results file generated"
        return 1
    fi
}

# Print summary
print_summary() {
    log_step "Analysis Summary"

    echo ""
    echo "Results Directory: $RESULTS_DIR"
    echo ""
    echo "Generated Files:"
    ls -la "$RESULTS_DIR"/*.{sarif,csv,json,log} 2>/dev/null | awk '{print "  " $NF ": " $5 " bytes"}' || true

    # Parse SARIF for summary if jq is available
    if [[ "$OUTPUT_FORMAT" == "sarif" ]] && command -v jq &> /dev/null && [[ -f "$RESULTS_DIR/codeql_results.sarif" ]]; then
        echo ""
        echo "Findings Summary:"

        TOTAL=$(jq '[.runs[].results[]] | length' "$RESULTS_DIR/codeql_results.sarif" 2>/dev/null || echo "0")
        echo "  Total findings: $TOTAL"

        if [[ "$TOTAL" -gt 0 ]]; then
            echo ""
            echo "  By Rule:"
            jq -r '[.runs[].results[].ruleId] | group_by(.) | map({rule: .[0], count: length}) | .[] | "    \(.rule): \(.count)"' \
                "$RESULTS_DIR/codeql_results.sarif" 2>/dev/null | head -20
        fi
    fi

    echo ""
    log_success "CodeQL analysis complete!"
}

# Main execution
main() {
    echo ""
    echo "============================================================"
    echo "       CODEQL ANALYSIS FOR VULNSHOP"
    echo "============================================================"
    echo ""

    check_prerequisites
    setup_results_dir
    create_database
    run_analysis
    print_summary
}

# Run main
main
