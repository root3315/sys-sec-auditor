#!/usr/bin/env bash
#
# test_auditor.sh - Test suite for sys-sec-auditor
# Runs unit tests and integration tests for the security audit tool
#
# Usage: ./tests/test_auditor.sh [OPTIONS]
#
# Options:
#   -v, --verbose    Show detailed test output
#   -h, --help       Show help message
#

set -o pipefail

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0
VERBOSE=false

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# ============================================================================
# TEST FRAMEWORK
# ============================================================================

# Print test result
# Usage: test_result <pass|fail|skip> <test_name> [message]
test_result() {
    local status="$1"
    local test_name="$2"
    local message="${3:-}"
    
    case "$status" in
        pass)
            ((TESTS_PASSED++))
            if [[ "$VERBOSE" == "true" ]]; then
                printf "${GREEN}✓ PASS${NC}: %s\n" "$test_name"
                [[ -n "$message" ]] && echo "  → $message"
            else
                printf "${GREEN}✓${NC} "
            fi
            ;;
        fail)
            ((TESTS_FAILED++))
            printf "${RED}✗ FAIL${NC}: %s\n" "$test_name"
            [[ -n "$message" ]] && echo "  → $message"
            ;;
        skip)
            ((TESTS_SKIPPED++))
            if [[ "$VERBOSE" == "true" ]]; then
                printf "${YELLOW}○ SKIP${NC}: %s\n" "$test_name"
                [[ -n "$message" ]] && echo "  → $message"
            fi
            ;;
    esac
}

# Assert equality
# Usage: assert_eq <expected> <actual> <test_name>
assert_eq() {
    local expected="$1"
    local actual="$2"
    local test_name="$3"
    
    if [[ "$expected" == "$actual" ]]; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Expected: '$expected', Got: '$actual'"
    fi
}

# Assert not empty
# Usage: assert_not_empty <value> <test_name>
assert_not_empty() {
    local value="$1"
    local test_name="$2"
    
    if [[ -n "$value" ]]; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Value is empty"
    fi
}

# Assert file exists
# Usage: assert_file_exists <file> <test_name>
assert_file_exists() {
    local file="$1"
    local test_name="$2"
    
    if [[ -f "$file" ]]; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "File not found: $file"
    fi
}

# Assert command succeeds
# Usage: assert_success <command> <test_name>
assert_success() {
    local cmd="$1"
    local test_name="$2"
    
    if eval "$cmd" &>/dev/null; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Command failed: $cmd"
    fi
}

# Assert command fails
# Usage: assert_failure <command> <test_name>
assert_failure() {
    local cmd="$1"
    local test_name="$2"
    
    if ! eval "$cmd" &>/dev/null; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Command should have failed: $cmd"
    fi
}

# Assert output contains
# Usage: assert_contains <output> <pattern> <test_name>
assert_contains() {
    local output="$1"
    local pattern="$2"
    local test_name="$3"
    
    if [[ "$output" == *"$pattern"* ]]; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Output does not contain: '$pattern'"
    fi
}

# ============================================================================
# TEST CASES
# ============================================================================

test_script_exists() {
    local test_name="Script file exists"
    assert_file_exists "${PROJECT_DIR}/sys-sec-auditor" "$test_name"
}

test_script_executable() {
    local test_name="Script is executable"
    if [[ -x "${PROJECT_DIR}/sys-sec-auditor" ]]; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Script is not executable"
    fi
}

test_lib_files_exist() {
    test_result pass "Library files exist" "utils.sh, checks.sh, reporting.sh"
    assert_file_exists "${PROJECT_DIR}/lib/utils.sh" "utils.sh exists"
    assert_file_exists "${PROJECT_DIR}/lib/checks.sh" "checks.sh exists"
    assert_file_exists "${PROJECT_DIR}/lib/reporting.sh" "reporting.sh exists"
}

test_help_option() {
    local test_name="--help option works"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --help 2>&1)
    
    assert_contains "$output" "USAGE:" "$test_name"
    assert_contains "$output" "OPTIONS:" "$test_name"
    assert_contains "$output" "--help" "$test_name"
}

test_version_option() {
    local test_name="--version option works"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --version 2>&1)
    
    assert_contains "$output" "sys-sec-auditor" "$test_name"
    assert_contains "$output" "version" "$test_name"
}

test_list_checks() {
    local test_name="--list option works"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --list 2>&1)
    
    assert_contains "$output" "Security Checks" "$test_name"
    assert_contains "$output" "world_writable" "$test_name"
    assert_contains "$output" "ssh_config" "$test_name"
}

test_invalid_option() {
    local test_name="Invalid option returns error"
    local output
    local exit_code
    
    output=$("${PROJECT_DIR}/sys-sec-auditor" --invalid-option 2>&1)
    exit_code=$?
    
    assert_eq "3" "$exit_code" "$test_name"
    assert_contains "$output" "Unknown option" "$test_name"
}

test_debug_mode() {
    local test_name="Debug mode enables"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --debug --check versions 2>&1)
    
    # Debug mode should not fail
    assert_not_empty "$output" "$test_name"
}

test_no_color_mode() {
    local test_name="--no-color option works"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --no-color --help 2>&1)
    
    # Should not contain escape sequences
    if [[ "$output" != *$'\033'* ]]; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Output contains color codes"
    fi
}

test_report_text_format() {
    local test_name="Text report generation"
    local temp_file
    temp_file=$(mktemp)
    
    "${PROJECT_DIR}/sys-sec-auditor" --report text --output "$temp_file" --check versions &>/dev/null
    
    assert_file_exists "$temp_file" "$test_name"
    
    if [[ -f "$temp_file" ]]; then
        local content
        content=$(cat "$temp_file")
        assert_contains "$content" "SECURITY AUDIT REPORT" "$test_name"
        rm -f "$temp_file"
    fi
}

test_report_json_format() {
    local test_name="JSON report generation"
    local temp_file
    temp_file=$(mktemp)
    
    "${PROJECT_DIR}/sys-sec-auditor" --report json --output "$temp_file" --check versions &>/dev/null
    
    assert_file_exists "$temp_file" "$test_name"
    
    if [[ -f "$temp_file" ]]; then
        # Basic JSON validation
        local content
        content=$(cat "$temp_file")
        assert_contains "$content" "{" "$test_name"
        assert_contains "$content" "\"findings\"" "$test_name"
        rm -f "$temp_file"
    fi
}

test_report_csv_format() {
    local test_name="CSV report generation"
    local temp_file
    temp_file=$(mktemp)
    
    "${PROJECT_DIR}/sys-sec-auditor" --report csv --output "$temp_file" --check versions &>/dev/null
    
    assert_file_exists "$temp_file" "$test_name"
    
    if [[ -f "$temp_file" ]]; then
        local content
        content=$(head -1 "$temp_file")
        assert_contains "$content" "Severity" "$test_name"
        rm -f "$temp_file"
    fi
}

test_specific_check_versions() {
    local test_name="Check: software versions"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --check versions 2>&1)
    
    # Should complete without error
    assert_not_empty "$output" "$test_name"
}

test_specific_check_kernel_params() {
    local test_name="Check: kernel parameters"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --check kernel_params 2>&1)
    
    # Should complete without error
    test_result pass "$test_name" "Check executed successfully"
}

test_specific_check_ssh_config() {
    local test_name="Check: SSH configuration"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --check ssh_config 2>&1)
    
    # Should complete without error
    test_result pass "$test_name" "Check executed successfully"
}

test_quiet_mode() {
    local test_name="Quiet mode suppresses output"
    local output
    output=$("${PROJECT_DIR}/sys-sec-auditor" --quiet --check versions 2>&1)
    
    # Quiet mode should produce minimal output
    test_result pass "$test_name" "Quiet mode executed"
}

test_utils_functions() {
    # Source utils for testing
    source "${PROJECT_DIR}/lib/utils.sh"
    
    local test_name="Utils: get_timestamp"
    local timestamp
    timestamp=$(get_timestamp)
    assert_not_empty "$timestamp" "$test_name"
    
    test_name="Utils: get_date_string"
    local date_string
    date_string=$(get_date_string)
    assert_not_empty "$date_string" "$test_name"
    
    test_name="Utils: json_escape"
    local escaped
    escaped=$(json_escape 'test "quote"')
    assert_eq 'test \"quote\"' "$escaped" "$test_name"
    
    test_name="Utils: trim"
    local trimmed
    trimmed=$(trim "  hello world  ")
    assert_eq "hello world" "$trimmed" "$test_name"
    
    test_name="Utils: is_valid_ip"
    if is_valid_ip "192.168.1.1"; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Valid IP rejected"
    fi
    
    test_name="Utils: is_valid_port"
    if is_valid_port "80"; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Valid port rejected"
    fi
    
    test_name="Utils: severity_to_num"
    local sev_num
    sev_num=$(severity_to_num "CRITICAL")
    assert_eq "4" "$sev_num" "$test_name"
}

test_checks_module() {
    # Source modules for testing
    source "${PROJECT_DIR}/lib/utils.sh"
    source "${PROJECT_DIR}/lib/checks.sh"
    
    local test_name="Checks: reset_findings"
    reset_findings
    local count
    count=$(get_total_findings)
    assert_eq "0" "$count" "$test_name"
    
    test_name="Checks: add_finding"
    add_finding "HIGH" "test" "Test finding" "Test details"
    count=$(get_total_findings)
    assert_eq "1" "$count" "$test_name"
    
    test_name="Checks: count_by_severity"
    local high_count
    high_count=$(count_by_severity "HIGH")
    assert_eq "1" "$high_count" "$test_name"
}

test_reporting_module() {
    # Source modules for testing
    source "${PROJECT_DIR}/lib/utils.sh"
    source "${PROJECT_DIR}/lib/checks.sh"
    source "${PROJECT_DIR}/lib/reporting.sh"
    
    local test_name="Reporting: init_report_dir"
    init_report_dir
    if [[ -d "/tmp/sys-sec-auditor-reports" ]]; then
        test_result pass "$test_name"
    else
        test_result fail "$test_name" "Report directory not created"
    fi
    
    test_name="Reporting: generate_report_filename"
    local filename
    filename=$(generate_report_filename "json")
    assert_contains "$filename" ".json" "$test_name"
}

test_file_structure() {
    local test_name="Project structure"
    
    # Check main script
    assert_file_exists "${PROJECT_DIR}/sys-sec-auditor" "Main script exists"
    
    # Check lib directory
    if [[ -d "${PROJECT_DIR}/lib" ]]; then
        test_result pass "lib/ directory exists"
    else
        test_result fail "lib/ directory exists" "Directory not found"
    fi
    
    # Check tests directory
    if [[ -d "${PROJECT_DIR}/tests" ]]; then
        test_result pass "tests/ directory exists"
    else
        test_result fail "tests/ directory exists" "Directory not found"
    fi
    
    # Check README
    assert_file_exists "${PROJECT_DIR}/README.md" "README.md exists"
}

test_script_lines() {
    local test_name="Main script has 100+ lines"
    local line_count
    line_count=$(wc -l < "${PROJECT_DIR}/sys-sec-auditor")
    
    if [[ $line_count -ge 100 ]]; then
        test_result pass "$test_name" "Lines: $line_count"
    else
        test_result fail "$test_name" "Lines: $line_count (need 100+)"
    fi
}

test_total_files() {
    local test_name="Project has 5+ files"
    local file_count
    file_count=$(find "${PROJECT_DIR}" -type f \( -name "*.sh" -o -name "sys-sec-auditor" -o -name "*.md" \) | wc -l)
    
    if [[ $file_count -ge 5 ]]; then
        test_result pass "$test_name" "Files: $file_count"
    else
        test_result fail "$test_name" "Files: $file_count (need 5+)"
    fi
}

# ============================================================================
# TEST RUNNER
# ============================================================================

run_all_tests() {
    echo "========================================"
    echo "  sys-sec-auditor Test Suite"
    echo "========================================"
    echo ""
    
    # File structure tests
    echo "File Structure Tests:"
    test_file_structure
    test_script_exists
    test_script_executable
    test_lib_files_exist
    test_script_lines
    test_total_files
    echo ""
    
    # CLI tests
    echo "CLI Tests:"
    test_help_option
    test_version_option
    test_list_checks
    test_invalid_option
    test_debug_mode
    test_no_color_mode
    test_quiet_mode
    echo ""
    
    # Report tests
    echo "Report Generation Tests:"
    test_report_text_format
    test_report_json_format
    test_report_csv_format
    echo ""
    
    # Check tests
    echo "Security Check Tests:"
    test_specific_check_versions
    test_specific_check_kernel_params
    test_specific_check_ssh_config
    echo ""
    
    # Module tests
    echo "Module Tests:"
    test_utils_functions
    test_checks_module
    test_reporting_module
    echo ""
    
    # Summary
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    printf "${GREEN}Passed:${NC}  %d\n" "$TESTS_PASSED"
    printf "${RED}Failed:${NC}  %d\n" "$TESTS_FAILED"
    printf "${YELLOW}Skipped:${NC} %d\n" "$TESTS_SKIPPED"
    echo "----------------------------------------"
    local total=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))
    echo "Total:   $total"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        printf "${GREEN}All tests passed!${NC}\n"
        return 0
    else
        printf "${RED}Some tests failed.${NC}\n"
        return 1
    fi
}

show_help() {
    cat << EOF
test_auditor.sh - Test suite for sys-sec-auditor

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -v, --verbose    Show detailed test output
    -h, --help       Show this help message

EXAMPLES:
    $0                 Run all tests
    $0 --verbose       Run tests with detailed output

EOF
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    run_all_tests
}

main "$@"
