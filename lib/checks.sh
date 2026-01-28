#!/usr/bin/env bash
#
# checks.sh - Security check functions for sys-sec-auditor
# Contains all vulnerability and misconfiguration scanning functions
#

# Include guard to prevent re-sourcing
if [[ -n "${_SYS_SEC_AUDITOR_CHECKS_LOADED:-}" ]]; then
    return 0
fi
readonly _SYS_SEC_AUDITOR_CHECKS_LOADED=1

# Source dependencies
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# Severity levels
readonly SEV_CRITICAL="CRITICAL"
readonly SEV_HIGH="HIGH"
readonly SEV_MEDIUM="MEDIUM"
readonly SEV_LOW="LOW"
readonly SEV_INFO="INFO"

# Global arrays to store findings
declare -a FINDINGS=()
declare -a FINDING_SEVERITIES=()
declare -a FINDING_CATEGORIES=()
declare -a FINDING_DETAILS=()

# Add a finding to the results
# Usage: add_finding <severity> <category> <description> [details]
add_finding() {
    local severity="$1"
    local category="$2"
    local description="$3"
    local details="${4:-}"
    
    FINDINGS+=("$description")
    FINDING_SEVERITIES+=("$severity")
    FINDING_CATEGORIES+=("$category")
    FINDING_DETAILS+=("$details")
    
    log_debug "Added finding: [$severity] $category - $description"
}

# Reset all findings
reset_findings() {
    FINDINGS=()
    FINDING_SEVERITIES=()
    FINDING_CATEGORIES=()
    FINDING_DETAILS=()
}

# Get finding count by severity
# Usage: count_by_severity <severity>
count_by_severity() {
    local target_sev="$1"
    local count=0
    for sev in "${FINDING_SEVERITIES[@]}"; do
        [[ "$sev" == "$target_sev" ]] && ((count++))
    done
    echo "$count"
}

# Get total finding count
get_total_findings() {
    echo "${#FINDINGS[@]}"
}

# ============================================================================
# FILE PERMISSION CHECKS
# ============================================================================

# Check for world-writable files in sensitive directories
# Usage: check_world_writable_files
check_world_writable_files() {
    print_subheader "World-Writable Files"
    
    local sensitive_dirs=("/etc" "/usr" "/bin" "/sbin" "/lib" "/lib64")
    local found=0
    
    for dir in "${sensitive_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r file; do
                [[ -n "$file" ]] || continue
                add_finding "$SEV_HIGH" "permissions" \
                    "World-writable file in sensitive directory: $file" \
                    "Directory: $dir | Permissions: $(get_file_perms "$file")"
                ((found++))
            done < <(find "$dir" -type f -perm -0002 2>/dev/null | head -50)
        fi
    done
    
    if [[ $found -eq 0 ]]; then
        log_success "No world-writable files found in sensitive directories"
    else
        log_warn "Found $found world-writable file(s) in sensitive directories"
    fi
    
    return $found
}

# Check for SUID/SGID binaries
# Usage: check_suid_sgid_binaries
check_suid_sgid_binaries() {
    print_subheader "SUID/SGID Binaries"
    
    local suid_count=0
    local sgid_count=0
    local known_safe_suid=(
        "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/chsh"
        "/usr/bin/chfn" "/usr/bin/newgrp" "/usr/bin/gpasswd" "/usr/bin/mount"
        "/usr/bin/umount" "/usr/bin/ping" "/usr/bin/ping6" "/usr/sbin/unix_chkpwd"
    )
    
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        
        local is_known_safe=false
        for safe in "${known_safe_suid[@]}"; do
            [[ "$file" == "$safe" ]] && is_known_safe=true && break
        done
        
        if [[ "$is_known_safe" == "false" ]]; then
            local perms
            perms=$(get_file_perms "$file")
            if [[ "${perms:0:1}" == "4" ]]; then
                add_finding "$SEV_MEDIUM" "permissions" \
                    "Non-standard SUID binary: $file" \
                    "Permissions: $perms | Owner: $(get_file_owner "$file")"
                ((suid_count++))
            elif [[ "${perms:0:1}" == "2" ]]; then
                add_finding "$SEV_LOW" "permissions" \
                    "Non-standard SGID binary: $file" \
                    "Permissions: $perms | Group: $(get_file_group "$file")"
                ((sgid_count++))
            fi
        fi
    done < <(find /usr /bin /sbin -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -100)
    
    log_info "SUID binaries (non-standard): $suid_count"
    log_info "SGID binaries (non-standard): $sgid_count"
    
    return $((suid_count + sgid_count))
}

# Check for insecure file permissions on critical files
# Usage: check_critical_file_permissions
check_critical_file_permissions() {
    print_subheader "Critical File Permissions"
    
    local critical_files=(
        "/etc/passwd:644"
        "/etc/shadow:640"
        "/etc/group:644"
        "/etc/gshadow:640"
        "/etc/sudoers:440"
        "/etc/ssh/sshd_config:600"
        "/etc/ssh/ssh_host_rsa_key:600"
        "/etc/ssh/ssh_host_ecdsa_key:600"
        "/etc/ssh/ssh_host_ed25519_key:600"
    )
    
    local issues=0
    for entry in "${critical_files[@]}"; do
        local file="${entry%%:*}"
        local expected_perms="${entry##*:}"
        
        if [[ -f "$file" ]]; then
            local actual_perms
            actual_perms=$(get_file_perms "$file")
            
            if [[ "$actual_perms" != "$expected_perms" ]]; then
                add_finding "$SEV_MEDIUM" "permissions" \
                    "Incorrect permissions on $file" \
                    "Expected: $expected_perms | Actual: $actual_perms"
                ((issues++))
            fi
        fi
    done
    
    if [[ $issues -eq 0 ]]; then
        log_success "All critical files have correct permissions"
    else
        log_warn "Found $issues file(s) with incorrect permissions"
    fi
    
    return $issues
}

# ============================================================================
# USER ACCOUNT CHECKS
# ============================================================================

# Check for users with empty passwords
# Usage: check_empty_passwords
check_empty_passwords() {
    print_subheader "Empty Password Accounts"
    
    local count=0
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r username password rest; do
            if [[ -z "$password" || "$password" == "!" || "$password" == "*" ]]; then
                continue
            fi
            if [[ "$password" == "" ]]; then
                add_finding "$SEV_CRITICAL" "accounts" \
                    "User account with empty password: $username" \
                    "Account may be accessible without authentication"
                ((count++))
            fi
        done < /etc/shadow
    else
        log_warn "Cannot read /etc/shadow (requires root)"
        return 1
    fi
    
    if [[ $count -eq 0 ]]; then
        log_success "No accounts with empty passwords found"
    else
        log_error "Found $count account(s) with empty passwords"
    fi
    
    return $count
}

# Check for UID 0 accounts (root equivalents)
# Usage: check_uid_zero_accounts
check_uid_zero_accounts() {
    print_subheader "UID 0 Accounts"
    
    local count=0
    while IFS=: read -r username _ uid rest; do
        if [[ "$uid" == "0" && "$username" != "root" ]]; then
            add_finding "$SEV_CRITICAL" "accounts" \
                "Non-root account with UID 0: $username" \
                "This account has full root privileges"
            ((count++))
        fi
    done < /etc/passwd
    
    if [[ $count -eq 0 ]]; then
        log_success "No unauthorized UID 0 accounts found"
    else
        log_error "Found $count non-root UID 0 account(s)"
    fi
    
    return $count
}

# Check for users without password aging
# Usage: check_password_aging
check_password_aging() {
    print_subheader "Password Aging Policy"
    
    local count=0
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r username password last_change min_age max_age warn inactive expire reserved; do
            [[ "$username" =~ ^[+#] ]] && continue
            [[ "$password" == "!" || "$password" == "*" || "$password" == "!!" ]] && continue
            
            if [[ "$max_age" == "" || "$max_age" == "99999" ]]; then
                add_finding "$SEV_LOW" "accounts" \
                    "User without password expiration: $username" \
                    "Password never expires (max_age: $max_age)"
                ((count++))
            fi
        done < /etc/shadow
    fi
    
    log_info "Users without password expiration: $count"
    return $count
}

# Check for locked accounts that should be reviewed
# Usage: check_locked_accounts
check_locked_accounts() {
    print_subheader "Locked/Disabled Accounts"
    
    local count=0
    if [[ -r /etc/shadow ]]; then
        while IFS=: read -r username password rest; do
            if [[ "$password" == "!"* || "$password" == "*" ]]; then
                ((count++))
                log_debug "Locked account: $username"
            fi
        done < /etc/shadow
    fi
    
    log_info "Total locked/disabled accounts: $count"
    return 0
}

# ============================================================================
# SERVICE AND PORT CHECKS
# ============================================================================

# Check for listening services
# Usage: check_listening_services
check_listening_services() {
    print_subheader "Listening Services"
    
    local count=0
    local services=()
    
    if command_exists ss; then
        while IFS= read -r line; do
            [[ "$line" =~ ^[A-Z] ]] && continue
            local port
            port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
            local addr
            addr=$(echo "$line" | awk '{print $5}' | sed 's/:[0-9]*$//')
            local process
            process=$(echo "$line" | awk '{print $7}')
            
            if [[ -n "$port" ]]; then
                if [[ "$addr" == "0.0.0.0" || "$addr" == "*" || "$addr" == "::" ]]; then
                    add_finding "$SEV_MEDIUM" "services" \
                        "Service listening on all interfaces: port $port" \
                        "Address: $addr | Process: $process"
                    ((count++))
                fi
                services+=("$port")
            fi
        done < <(ss -tuln 2>/dev/null)
    elif command_exists netstat; then
        while IFS= read -r line; do
            [[ "$line" =~ ^tcp|^udp ]] || continue
            local port
            port=$(echo "$line" | awk '{print $4}' | grep -oE '[0-9]+$')
            local addr
            addr=$(echo "$line" | awk '{print $4}' | sed 's/:[0-9]*$//')
            
            if [[ -n "$port" ]]; then
                if [[ "$addr" == "0.0.0.0" || "$addr" == "*" || "$addr" == "::" ]]; then
                    add_finding "$SEV_MEDIUM" "services" \
                        "Service listening on all interfaces: port $port" \
                        "Address: $addr"
                    ((count++))
                fi
            fi
        done < <(netstat -tuln 2>/dev/null)
    else
        log_warn "Neither ss nor netstat available"
        return 1
    fi
    
    log_info "Services bound to all interfaces: $count"
    return $count
}

# Check for insecure services
# Usage: check_insecure_services
check_insecure_services() {
    print_subheader "Insecure Services"
    
    local insecure_ports=(
        "21:FTP"
        "23:Telnet"
        "25:SMTP"
        "69:TFTP"
        "111:RPC"
        "139:NetBIOS"
        "445:SMB"
        "512:rexec"
        "513:rlogin"
        "514:rsh"
    )
    
    local count=0
    local listening_ports=()
    
    if command_exists ss; then
        while IFS= read -r line; do
            local port
            port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
            [[ -n "$port" ]] && listening_ports+=("$port")
        done < <(ss -tuln 2>/dev/null)
    fi
    
    for entry in "${insecure_ports[@]}"; do
        local port="${entry%%:*}"
        local service="${entry##*:}"
        
        for listen_port in "${listening_ports[@]}"; do
            if [[ "$listen_port" == "$port" ]]; then
                add_finding "$SEV_HIGH" "services" \
                    "Insecure service detected: $service (port $port)" \
                    "Consider disabling or replacing with secure alternative"
                ((count++))
                break
            fi
        done
    done
    
    if [[ $count -eq 0 ]]; then
        log_success "No known insecure services detected"
    else
        log_warn "Found $count insecure service(s)"
    fi
    
    return $count
}

# ============================================================================
# SYSTEM CONFIGURATION CHECKS
# ============================================================================

# Check kernel security parameters
# Usage: check_kernel_params
check_kernel_params() {
    print_subheader "Kernel Security Parameters"
    
    local params=(
        "net.ipv4.ip_forward:0:IP forwarding enabled"
        "net.ipv4.conf.all.send_redirects:0:ICMP redirects enabled"
        "net.ipv4.conf.default.send_redirects:0:ICMP redirects enabled (default)"
        "net.ipv4.conf.all.accept_source_route:0:Source routing enabled"
        "net.ipv4.conf.default.accept_source_route:0:Source routing enabled (default)"
        "net.ipv4.conf.all.accept_redirects:0:ICMP redirects accepted"
        "net.ipv4.conf.default.accept_redirects:0:ICMP redirects accepted (default)"
        "net.ipv4.conf.all.log_martians:1:Martian packet logging disabled"
        "net.ipv4.icmp_echo_ignore_broadcasts:1:Broadcast ping response enabled"
        "kernel.randomize_va_space:2:ASLR disabled or partial"
    )
    
    local count=0
    for entry in "${params[@]}"; do
        local param="${entry%%:*}"
        local expected="${entry#*:}"
        expected="${expected%%:*}"
        local desc="${entry##*:}"
        
        local current
        current=$(sysctl -n "$param" 2>/dev/null)
        
        if [[ -n "$current" && "$current" != "$expected" ]]; then
            local severity="$SEV_MEDIUM"
            [[ "$param" == *"randomize_va_space"* ]] && severity="$SEV_HIGH"
            
            add_finding "$severity" "kernel" \
                "$desc: $param" \
                "Expected: $expected | Current: $current"
            ((count++))
        fi
    done
    
    log_info "Kernel parameter issues: $count"
    return $count
}

# Check for outdated software
# Usage: check_software_versions
check_software_versions() {
    print_subheader "Software Version Check"
    
    local count=0
    
    # Check SSH version
    if command_exists ssh; then
        local ssh_version
        ssh_version=$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9.]+' | head -1)
        if [[ -n "$ssh_version" ]]; then
            log_debug "SSH version: $ssh_version"
        fi
    fi
    
    # Check bash version
    if [[ -x /bin/bash ]]; then
        local bash_version
        bash_version=$(/bin/bash --version | head -1)
        log_debug "Bash: $bash_version"
    fi
    
    # Check for package manager updates (informational)
    if command_exists apt; then
        local updates
        updates=$(apt list --upgradable 2>/dev/null | grep -c "upgradable" 2>/dev/null || echo "0")
        updates=$(echo "$updates" | tr -d '[:space:]')
        if [[ -n "$updates" && "$updates" -gt 0 ]] 2>/dev/null; then
            add_finding "$SEV_LOW" "updates" \
                "System has $updates package(s) pending update" \
                "Run 'apt list --upgradable' to see details"
            ((count++))
        fi
    elif command_exists yum || command_exists dnf; then
        local updates
        updates=$(yum check-update 2>/dev/null | grep -c "^[a-z]" 2>/dev/null || echo "0")
        updates=$(echo "$updates" | tr -d '[:space:]')
        if [[ -n "$updates" && "$updates" -gt 0 ]] 2>/dev/null; then
            add_finding "$SEV_LOW" "updates" \
                "System has packages pending update" \
                "Run 'yum check-update' to see details"
            ((count++))
        fi
    fi
    
    return $count
}

# Check SSH configuration
# Usage: check_ssh_config
check_ssh_config() {
    print_subheader "SSH Configuration"
    
    local sshd_config="/etc/ssh/sshd_config"
    local count=0
    
    if [[ ! -f "$sshd_config" ]]; then
        log_debug "SSH config not found at $sshd_config"
        return 0
    fi
    
    # Check for root login
    if grep -qE "^PermitRootLogin\s+yes" "$sshd_config" 2>/dev/null; then
        add_finding "$SEV_HIGH" "ssh" \
            "SSH root login is permitted" \
            "File: $sshd_config | Setting: PermitRootLogin yes"
        ((count++))
    fi
    
    # Check for password authentication
    if grep -qE "^PasswordAuthentication\s+yes" "$sshd_config" 2>/dev/null; then
        add_finding "$SEV_MEDIUM" "ssh" \
            "SSH password authentication is enabled" \
            "Consider using key-based authentication only"
        ((count++))
    fi
    
    # Check for empty passwords
    if grep -qE "^PermitEmptyPasswords\s+yes" "$sshd_config" 2>/dev/null; then
        add_finding "$SEV_CRITICAL" "ssh" \
            "SSH permits empty passwords" \
            "File: $sshd_config | Setting: PermitEmptyPasswords yes"
        ((count++))
    fi
    
    # Check for protocol version
    if grep -qE "^Protocol\s+1" "$sshd_config" 2>/dev/null; then
        add_finding "$SEV_HIGH" "ssh" \
            "SSH protocol version 1 is enabled" \
            "Protocol 1 is insecure, use Protocol 2 only"
        ((count++))
    fi
    
    if [[ $count -eq 0 ]]; then
        log_success "SSH configuration appears secure"
    else
        log_warn "Found $count SSH configuration issue(s)"
    fi
    
    return $count
}

# Check cron jobs for security issues
# Usage: check_cron_jobs
check_cron_jobs() {
    print_subheader "Cron Job Security"
    
    local count=0
    local cron_dirs=("/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly" "/etc/cron.monthly")
    
    # Check world-writable cron files
    for dir in "${cron_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r file; do
                [[ -n "$file" ]] || continue
                add_finding "$SEV_HIGH" "cron" \
                    "World-writable cron file: $file" \
                    "Permissions: $(get_file_perms "$file")"
                ((count++))
            done < <(find "$dir" -type f -perm -0002 2>/dev/null)
        fi
    done
    
    # Check /etc/crontab
    if [[ -f /etc/crontab ]]; then
        local perms
        perms=$(get_file_perms /etc/crontab)
        if [[ "$perms" != "600" && "$perms" != "644" ]]; then
            add_finding "$SEV_MEDIUM" "cron" \
                "Unusual permissions on /etc/crontab" \
                "Permissions: $perms"
            ((count++))
        fi
    fi
    
    log_info "Cron security issues: $count"
    return $count
}

# ============================================================================
# LOG AND AUDIT CHECKS
# ============================================================================

# Check logging configuration
# Usage: check_logging_config
check_logging_config() {
    print_subheader "Logging Configuration"
    
    local count=0
    
    # Check if rsyslog/syslog is running
    if ! pgrep -x "rsyslogd" &>/dev/null && ! pgrep -x "syslogd" &>/dev/null; then
        add_finding "$SEV_MEDIUM" "logging" \
            "System logging daemon not running" \
            "Consider starting rsyslog or syslog-ng"
        ((count++))
    fi
    
    # Check for important log files
    local log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/syslog" "/var/log/messages")
    for log in "${log_files[@]}"; do
        if [[ -f "$log" ]]; then
            local perms
            perms=$(get_file_perms "$log")
            if [[ "${perms:1:2}" == *"6"* || "${perms:1:2}" == *"7"* ]]; then
                add_finding "$SEV_LOW" "logging" \
                    "Log file may be world-readable: $log" \
                    "Permissions: $perms"
                ((count++))
            fi
        fi
    done
    
    # Check auditd
    if ! command_exists auditctl && ! pgrep -x "auditd" &>/dev/null; then
        add_finding "$SEV_LOW" "logging" \
            "Audit daemon (auditd) not running" \
            "Consider enabling auditd for security monitoring"
        ((count++))
    fi
    
    return $count
}

# Check for failed login attempts
# Usage: check_failed_logins
check_failed_logins() {
    print_subheader "Failed Login Analysis"
    
    local count=0
    local auth_log=""
    
    if [[ -f /var/log/auth.log ]]; then
        auth_log="/var/log/auth.log"
    elif [[ -f /var/log/secure ]]; then
        auth_log="/var/log/secure"
    fi
    
    if [[ -n "$auth_log" && -r "$auth_log" ]]; then
        local failed_count
        failed_count=$(grep -c "Failed password\|authentication failure" "$auth_log" 2>/dev/null || echo "0")
        
        if [[ "$failed_count" -gt 100 ]]; then
            add_finding "$SEV_MEDIUM" "accounts" \
                "High number of failed login attempts: $failed_count" \
                "Log file: $auth_log | Consider investigating potential brute force"
            ((count++))
        else
            log_info "Failed login attempts (recent): $failed_count"
        fi
    else
        log_debug "Auth log not found or not readable"
    fi
    
    return $count
}

# ============================================================================
# RUN ALL CHECKS
# ============================================================================

# Run all security checks
# Usage: run_all_checks
run_all_checks() {
    reset_findings
    
    print_header "System Security Audit"
    
    log_info "Hostname: $(get_hostname)"
    log_info "OS: $(get_os_name)"
    log_info "Kernel: $(get_kernel_version)"
    log_info "Audit started: $(get_timestamp)"
    
    if ! check_root; then
        log_warn "Not running as root - some checks may be limited"
    fi
    
    # File permission checks
    check_world_writable_files
    check_suid_sgid_binaries
    check_critical_file_permissions
    
    # User account checks
    check_uid_zero_accounts
    check_password_aging
    check_locked_accounts
    
    # Service checks
    check_listening_services
    check_insecure_services
    
    # System configuration
    check_kernel_params
    check_ssh_config
    check_cron_jobs
    
    # Logging
    check_logging_config
    check_failed_logins
    
    # Software
    check_software_versions
    
    print_header "Audit Summary"
    log_info "Total findings: $(get_total_findings)"
    log_info "Critical: $(count_by_severity "$SEV_CRITICAL")"
    log_info "High: $(count_by_severity "$SEV_HIGH")"
    log_info "Medium: $(count_by_severity "$SEV_MEDIUM")"
    log_info "Low: $(count_by_severity "$SEV_LOW")"
    log_info "Info: $(count_by_severity "$SEV_INFO")"
}

# Export functions for use by other scripts
export -f add_finding reset_findings count_by_severity get_total_findings
export -f check_world_writable_files check_suid_sgid_binaries check_critical_file_permissions
export -f check_empty_passwords check_uid_zero_accounts check_password_aging
export -f check_listening_services check_insecure_services
export -f check_kernel_params check_ssh_config check_cron_jobs
export -f check_logging_config check_failed_logins check_software_versions
export -f run_all_checks
