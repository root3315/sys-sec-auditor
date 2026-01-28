#!/usr/bin/env bash
#
# reporting.sh - Report generation functions for sys-sec-auditor
# Handles output formatting and report generation in various formats
#

# Include guard to prevent re-sourcing
if [[ -n "${_SYS_SEC_AUDITOR_REPORTING_LOADED:-}" ]]; then
    return 0
fi
readonly _SYS_SEC_AUDITOR_REPORTING_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# Report output directory (can be overridden)
REPORT_DIR="${REPORT_DIR:-/tmp/sys-sec-auditor-reports}"
REPORT_FORMAT="${REPORT_FORMAT:-text}"

# Ensure report directory exists
init_report_dir() {
    if [[ ! -d "$REPORT_DIR" ]]; then
        mkdir -p "$REPORT_DIR"
        log_debug "Created report directory: $REPORT_DIR"
    fi
}

# Generate unique report filename
# Usage: generate_report_filename [format]
generate_report_filename() {
    local format="${1:-$REPORT_FORMAT}"
    local timestamp
    timestamp=$(get_date_string)
    local hostname
    hostname=$(get_hostname | tr -cd '[:alnum:]-')
    
    echo "${REPORT_DIR}/audit_${hostname}_${timestamp}.${format}"
}

# ============================================================================
# TEXT REPORT GENERATION
# ============================================================================

# Generate text format report
# Usage: generate_text_report <output_file>
generate_text_report() {
    local output_file="$1"
    
    {
        print_text_header
        print_system_info
        print_findings_summary
        print_detailed_findings
        print_recommendations
        print_text_footer
    } > "$output_file"
    
    # Log message is handled by caller
}

# Print text report header
print_text_header() {
    local width=70
    local line=""
    for ((i=0; i<width; i++)); do line+="="; done
    
    cat << EOF
$line
                    SYSTEM SECURITY AUDIT REPORT
$line

Generated: $(get_timestamp)
Hostname:  $(get_hostname)
OS:        $(get_os_name)
Kernel:    $(get_kernel_version)

$line
EOF
}

# Print system information section
print_system_info() {
    cat << EOF

SYSTEM INFORMATION
------------------
EOF
    
    echo "Uptime:      $(uptime 2>/dev/null || echo 'N/A')"
    echo "Users:       $(who 2>/dev/null | wc -l || echo 'N/A') logged in"
    echo "Processes:   $(ps aux 2>/dev/null | wc -l || echo 'N/A')"
    
    # Network interfaces
    echo ""
    echo "Network Interfaces:"
    if command_exists ip; then
        ip -brief addr 2>/dev/null | while read -r line; do
            echo "  $line"
        done
    elif command_exists ifconfig; then
        ifconfig 2>/dev/null | grep -E "^[a-z]|inet " | head -20
    fi
}

# Print findings summary
print_findings_summary() {
    local total
    total=$(get_total_findings 2>/dev/null || echo "0")
    local critical
    critical=$(count_by_severity "CRITICAL" 2>/dev/null || echo "0")
    local high
    high=$(count_by_severity "HIGH" 2>/dev/null || echo "0")
    local medium
    medium=$(count_by_severity "MEDIUM" 2>/dev/null || echo "0")
    local low
    low=$(count_by_severity "LOW" 2>/dev/null || echo "0")
    
    cat << EOF

FINDINGS SUMMARY
----------------
Total Findings: $total

  CRITICAL: $critical
  HIGH:     $high
  MEDIUM:   $medium
  LOW:      $low

EOF
    
    # Risk score calculation
    local risk_score=$((critical * 10 + high * 5 + medium * 2 + low))
    local risk_level="LOW"
    
    if [[ $risk_score -ge 50 ]]; then
        risk_level="CRITICAL"
    elif [[ $risk_score -ge 30 ]]; then
        risk_level="HIGH"
    elif [[ $risk_score -ge 15 ]]; then
        risk_level="MEDIUM"
    fi
    
    echo "Risk Score: $risk_score ($risk_level)"
    echo ""
}

# Print detailed findings
print_detailed_findings() {
    cat << EOF

DETAILED FINDINGS
-----------------
EOF
    
    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        echo "No security issues found."
        return
    fi
    
    local current_category=""
    local finding_num=0
    
    for i in "${!FINDINGS[@]}"; do
        local category="${FINDING_CATEGORIES[$i]}"
        local severity="${FINDING_SEVERITIES[$i]}"
        local description="${FINDINGS[$i]}"
        local details="${FINDING_DETAILS[$i]}"
        
        # Print category header if changed
        if [[ "$category" != "$current_category" ]]; then
            echo ""
            echo "[$category]"
            echo "$(printf '=%.0s' {1..50})"
            current_category="$category"
        fi
        
        ((finding_num++))
        
        # Severity indicator
        local sev_icon="[!]"
        case "$severity" in
            CRITICAL) sev_icon="[!!!]" ;;
            HIGH)     sev_icon="[!!]" ;;
            MEDIUM)   sev_icon="[!]" ;;
            LOW)      sev_icon="[-]" ;;
            INFO)     sev_icon="[i]" ;;
        esac
        
        echo ""
        echo "  $sev_icon [$severity] #$finding_num: $description"
        
        if [[ -n "$details" ]]; then
            echo "      Details: $details"
        fi
    done
    
    echo ""
}

# Print recommendations
print_recommendations() {
    cat << EOF

RECOMMENDATIONS
---------------
EOF
    
    local critical
    critical=$(count_by_severity "CRITICAL" 2>/dev/null || echo "0")
    local high
    high=$(count_by_severity "HIGH" 2>/dev/null || echo "0")
    
    if [[ $critical -gt 0 ]]; then
        cat << 'EOF'
IMMEDIATE ACTION REQUIRED:
  - Address all CRITICAL findings before system goes into production
  - Review and remediate unauthorized UID 0 accounts
  - Fix any empty password configurations
  - Disable insecure services (telnet, FTP, rsh)

EOF
    fi
    
    if [[ $high -gt 0 ]]; then
        cat << 'EOF'
HIGH PRIORITY:
  - Review and fix world-writable files in sensitive directories
  - Audit non-standard SUID/SGID binaries
  - Harden SSH configuration
  - Enable firewall rules for exposed services

EOF
    fi
    
    cat << 'EOF'
GENERAL RECOMMENDATIONS:
  - Enable and configure auditd for security monitoring
  - Implement password expiration policies
  - Regular security updates and patching
  - Review and minimize listening services
  - Implement log rotation and centralized logging
  - Consider implementing SELinux or AppArmor

EOF
}

# Print text report footer
print_text_footer() {
    local width=70
    local line=""
    for ((i=0; i<width; i++)); do line+="="; done
    
    cat << EOF
$line
Report generated by sys-sec-auditor
Audit completed: $(get_timestamp)
$line
EOF
}

# ============================================================================
# JSON REPORT GENERATION
# ============================================================================

# Generate JSON format report
# Usage: generate_json_report <output_file>
generate_json_report() {
    local output_file="$1"
    
    {
        echo "{"
        echo "  \"report\": {"
        echo "    \"type\": \"security_audit\","
        echo "    \"version\": \"1.0\","
        echo "    \"generated\": \"$(get_timestamp)\","
        echo "    \"hostname\": \"$(json_escape "$(get_hostname)")\","
        echo "    \"os\": \"$(json_escape "$(get_os_name)")\","
        echo "    \"kernel\": \"$(json_escape "$(get_kernel_version)")\""
        echo "  },"
        
        # Summary
        local total
        total=$(get_total_findings 2>/dev/null || echo "0")
        local critical
        critical=$(count_by_severity "CRITICAL" 2>/dev/null || echo "0")
        local high
        high=$(count_by_severity "HIGH" 2>/dev/null || echo "0")
        local medium
        medium=$(count_by_severity "MEDIUM" 2>/dev/null || echo "0")
        local low
        low=$(count_by_severity "LOW" 2>/dev/null || echo "0")
        
        echo "  \"summary\": {"
        echo "    \"total\": $total,"
        echo "    \"critical\": $critical,"
        echo "    \"high\": $high,"
        echo "    \"medium\": $medium,"
        echo "    \"low\": $low"
        echo "  },"
        
        # Findings
        echo "  \"findings\": ["
        
        local first=true
        for i in "${!FINDINGS[@]}"; do
            if [[ "$first" == "true" ]]; then
                first=false
            else
                echo ","
            fi
            
            local category
            category=$(json_escape "${FINDING_CATEGORIES[$i]}")
            local severity
            severity=$(json_escape "${FINDING_SEVERITIES[$i]}")
            local description
            description=$(json_escape "${FINDINGS[$i]}")
            local details
            details=$(json_escape "${FINDING_DETAILS[$i]}")
            
            printf "    {\n"
            printf "      \"id\": %d,\n" "$((i + 1))"
            printf "      \"category\": \"%s\",\n" "$category"
            printf "      \"severity\": \"%s\",\n" "$severity"
            printf "      \"description\": \"%s\",\n" "$description"
            printf "      \"details\": \"%s\"\n" "$details"
            printf "    }"
        done
        
        echo ""
        echo "  ]"
        echo "}"
    } > "$output_file"
    
    # Log message is handled by caller
}

# ============================================================================
# CSV REPORT GENERATION
# ============================================================================

# Generate CSV format report
# Usage: generate_csv_report <output_file>
generate_csv_report() {
    local output_file="$1"
    
    {
        # Header
        echo "ID,Severity,Category,Description,Details"
        
        # Findings
        for i in "${!FINDINGS[@]}"; do
            local severity="${FINDING_SEVERITIES[$i]}"
            local category="${FINDING_CATEGORIES[$i]}"
            local description="${FINDINGS[$i]}"
            local details="${FINDING_DETAILS[$i]}"
            
            # Escape quotes and wrap in quotes
            description="${description//\"/\"\"}"
            details="${details//\"/\"\"}"
            
            echo "$((i + 1)),\"$severity\",\"$category\",\"$description\",\"$details\""
        done
    } > "$output_file"
    
    # Log message is handled by caller
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

# Generate HTML format report
# Usage: generate_html_report <output_file>
generate_html_report() {
    local output_file="$1"
    
    {
        cat << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .meta { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .meta p { margin: 5px 0; }
        .summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
        .stat { padding: 20px; border-radius: 8px; text-align: center; min-width: 100px; }
        .stat-critical { background: #dc3545; color: white; }
        .stat-high { background: #fd7e14; color: white; }
        .stat-medium { background: #ffc107; color: #333; }
        .stat-low { background: #28a745; color: white; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        tr:hover { background: #f8f9fa; }
        .severity { padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 600; }
        .severity-CRITICAL { background: #dc3545; color: white; }
        .severity-HIGH { background: #fd7e14; color: white; }
        .severity-MEDIUM { background: #ffc107; color: #333; }
        .severity-LOW { background: #28a745; color: white; }
        .severity-INFO { background: #17a2b8; color: white; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Security Audit Report</h1>
        
        <div class="meta">
            <p><strong>Generated:</strong> $(get_timestamp)</p>
            <p><strong>Hostname:</strong> $(get_hostname)</p>
            <p><strong>OS:</strong> $(get_os_name)</p>
            <p><strong>Kernel:</strong> $(get_kernel_version)</p>
        </div>
EOF
        
        # Summary statistics
        local total
        total=$(get_total_findings 2>/dev/null || echo "0")
        local critical
        critical=$(count_by_severity "CRITICAL" 2>/dev/null || echo "0")
        local high
        high=$(count_by_severity "HIGH" 2>/dev/null || echo "0")
        local medium
        medium=$(count_by_severity "MEDIUM" 2>/dev/null || echo "0")
        local low
        low=$(count_by_severity "LOW" 2>/dev/null || echo "0")
        
        cat << EOF
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="stat stat-critical">
                <div class="stat-number">$critical</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat stat-high">
                <div class="stat-number">$high</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat stat-medium">
                <div class="stat-number">$medium</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat stat-low">
                <div class="stat-number">$low</div>
                <div class="stat-label">Low</div>
            </div>
        </div>
        
        <h2>Findings ($total total)</h2>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Description</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
EOF
        
        for i in "${!FINDINGS[@]}"; do
            local severity="${FINDING_SEVERITIES[$i]}"
            local category="${FINDING_CATEGORIES[$i]}"
            local description="${FINDINGS[$i]}"
            local details="${FINDING_DETAILS[$i]}"
            
            # Escape HTML
            description="${description//&/&amp;}"
            description="${description//</&lt;}"
            description="${description//>/&gt;}"
            details="${details//&/&amp;}"
            details="${details//</&lt;}"
            details="${details//>/&gt;}"
            
            cat << EOF
                <tr>
                    <td>$((i + 1))</td>
                    <td><span class="severity severity-$severity">$severity</span></td>
                    <td>$category</td>
                    <td>$description</td>
                    <td>$details</td>
                </tr>
EOF
        done
        
        cat << 'EOF'
            </tbody>
        </table>
        
        <div class="footer">
            <p>Report generated by sys-sec-auditor</p>
        </div>
    </div>
</body>
</html>
EOF
    } > "$output_file"
    
    # Log message is handled by caller
}

# ============================================================================
# MAIN REPORT GENERATOR
# ============================================================================

# Generate report in specified format
# Usage: generate_report [format] [output_file]
generate_report() {
    local format="${1:-$REPORT_FORMAT}"
    local output_file="$2"
    
    init_report_dir
    
    if [[ -z "$output_file" ]]; then
        output_file=$(generate_report_filename "$format")
    fi
    
    case "$format" in
        text|txt)
            generate_text_report "$output_file"
            ;;
        json)
            generate_json_report "$output_file"
            ;;
        csv)
            generate_csv_report "$output_file"
            ;;
        html)
            generate_html_report "$output_file"
            ;;
        *)
            log_error "Unknown format: $format"
            log_info "Supported formats: text, json, csv, html"
            return 1
            ;;
    esac
    
    echo "$output_file"
}

# Generate all report formats
# Usage: generate_all_reports [output_dir]
generate_all_reports() {
    local output_dir="${1:-$REPORT_DIR}"
    local timestamp
    timestamp=$(get_date_string)
    local hostname
    hostname=$(get_hostname | tr -cd '[:alnum:]-')
    
    init_report_dir
    
    local files=()
    files+=("$(generate_report text "${output_dir}/audit_${hostname}_${timestamp}.txt")")
    files+=("$(generate_report json "${output_dir}/audit_${hostname}_${timestamp}.json")")
    files+=("$(generate_report csv "${output_dir}/audit_${hostname}_${timestamp}.csv")")
    files+=("$(generate_report html "${output_dir}/audit_${hostname}_${timestamp}.html")")
    
    log_info "Generated ${#files[@]} report files in: $output_dir"
}

# Print findings to stdout (for interactive use)
# Usage: print_findings
print_findings() {
    if [[ ${#FINDINGS[@]} -eq 0 ]]; then
        log_success "No security issues found!"
        return 0
    fi
    
    echo ""
    print_header "Security Findings"
    
    local current_category=""
    for i in "${!FINDINGS[@]}"; do
        local category="${FINDING_CATEGORIES[$i]}"
        local severity="${FINDING_SEVERITIES[$i]}"
        local description="${FINDINGS[$i]}"
        local details="${FINDING_DETAILS[$i]}"
        
        if [[ "$category" != "$current_category" ]]; then
            print_subheader "$category"
            current_category="$category"
        fi
        
        local color="$COLOR_GREEN"
        case "$severity" in
            CRITICAL) color="$COLOR_RED" ;;
            HIGH)     color="$COLOR_RED" ;;
            MEDIUM)   color="$COLOR_YELLOW" ;;
            LOW)      color="$COLOR_BLUE" ;;
        esac
        
        printf "  %b[%s]%b %s\n" "$color" "$severity" "$COLOR_RESET" "$description"
        [[ -n "$details" ]] && echo "    → $details"
    done
}

# Export functions
export -f init_report_dir generate_report_filename
export -f generate_text_report generate_json_report generate_csv_report generate_html_report
export -f generate_report generate_all_reports print_findings
export -f print_text_header print_findings_summary print_detailed_findings
