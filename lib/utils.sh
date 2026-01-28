#!/usr/bin/env bash
#
# utils.sh - Utility functions for sys-sec-auditor
# Provides common helper functions used across the audit tool
#

# Include guard to prevent re-sourcing
if [[ -n "${_SYS_SEC_AUDITOR_UTILS_LOADED:-}" ]]; then
    return 0
fi
readonly _SYS_SEC_AUDITOR_UTILS_LOADED=1

# Color codes for terminal output
readonly COLOR_RESET="\033[0m"
readonly COLOR_RED="\033[31m"
readonly COLOR_GREEN="\033[32m"
readonly COLOR_YELLOW="\033[33m"
readonly COLOR_BLUE="\033[34m"
readonly COLOR_CYAN="\033[36m"
readonly COLOR_BOLD="\033[1m"

# Logging levels
readonly LOG_INFO="INFO"
readonly LOG_WARN="WARN"
readonly LOG_ERROR="ERROR"
readonly LOG_DEBUG="DEBUG"

# Global debug flag (set by main script)
DEBUG_ENABLED="${DEBUG_ENABLED:-false}"

# Print a message with color
# Usage: print_color <color> <message>
print_color() {
    local color="$1"
    local message="$2"
    printf "%b%s%b\n" "$color" "$message" "$COLOR_RESET"
}

# Print info message
# Usage: log_info <message>
log_info() {
    printf "%b[INFO]%b %s\n" "$COLOR_BLUE" "$COLOR_RESET" "$1"
}

# Print warning message
# Usage: log_warn <message>
log_warn() {
    printf "%b[WARN]%b %s\n" "$COLOR_YELLOW" "$COLOR_RESET" "$1"
}

# Print error message
# Usage: log_error <message>
log_error() {
    printf "%b[ERROR]%b %s\n" "$COLOR_RED" "$COLOR_RESET" "$1" >&2
}

# Print success message
# Usage: log_success <message>
log_success() {
    printf "%b[OK]%b %s\n" "$COLOR_GREEN" "$COLOR_RESET" "$1"
}

# Print debug message (only if DEBUG_ENABLED is true)
# Usage: log_debug <message>
log_debug() {
    if [[ "$DEBUG_ENABLED" == "true" ]]; then
        printf "%b[DEBUG]%b %s\n" "$COLOR_CYAN" "$COLOR_RESET" "$1"
    fi
}

# Print section header
# Usage: print_header <title>
print_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    local line=""
    
    for ((i=0; i<width; i++)); do
        line+="="
    done
    
    printf "\n%b%s%b\n" "$COLOR_BOLD" "$line" "$COLOR_RESET"
    printf "%b%*s%b %s\n" "$COLOR_BOLD" "$padding" "" "$COLOR_RESET" "$title"
    printf "%b%s%b\n\n" "$COLOR_BOLD" "$line" "$COLOR_RESET"
}

# Print sub-section header
# Usage: print_subheader <title>
print_subheader() {
    local title="$1"
    printf "\n%b--- %s ---%b\n" "$COLOR_CYAN" "$title" "$COLOR_RESET"
}

# Check if running as root
# Returns: 0 if root, 1 otherwise
check_root() {
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi
    return 1
}

# Check if a command exists
# Usage: command_exists <command>
# Returns: 0 if exists, 1 otherwise
command_exists() {
    command -v "$1" &>/dev/null
}

# Get current timestamp in ISO format
# Usage: get_timestamp
get_timestamp() {
    date +"%Y-%m-%dT%H:%M:%S%z"
}

# Get current date for filenames
# Usage: get_date_string
get_date_string() {
    date +"%Y%m%d_%H%M%S"
}

# Check if a file is readable
# Usage: is_readable <file>
# Returns: 0 if readable, 1 otherwise
is_readable() {
    [[ -r "$1" ]]
}

# Check if a file exists
# Usage: file_exists <file>
# Returns: 0 if exists, 1 otherwise
file_exists() {
    [[ -f "$1" ]]
}

# Check if a directory exists
# Usage: dir_exists <dir>
# Returns: 0 if exists, 1 otherwise
dir_exists() {
    [[ -d "$1" ]]
}

# Safely read a file, handling permission errors
# Usage: safe_read_file <file>
# Output: file contents or empty string on error
safe_read_file() {
    local file="$1"
    if [[ -r "$file" ]]; then
        cat "$file" 2>/dev/null
    else
        log_debug "Cannot read file: $file (permission denied)"
        return 1
    fi
}

# Escape special characters for JSON output
# Usage: json_escape <string>
json_escape() {
    local string="$1"
    string="${string//\\/\\\\}"
    string="${string//\"/\\\"}"
    string="${string//$'\n'/\\n}"
    string="${string//$'\r'/\\r}"
    string="${string//$'\t'/\\t}"
    printf '%s' "$string"
}

# Trim whitespace from string
# Usage: trim <string>
trim() {
    local var="$1"
    var="${var#"${var%%[![:space:]]*}"}"
    var="${var%"${var##*[![:space:]]}"}"
    printf '%s' "$var"
}

# Convert severity to numeric value for sorting
# Usage: severity_to_num <severity>
severity_to_num() {
    case "$1" in
        CRITICAL) echo 4 ;;
        HIGH)     echo 3 ;;
        MEDIUM)   echo 2 ;;
        LOW)      echo 1 ;;
        INFO)     echo 0 ;;
        *)        echo 0 ;;
    esac
}

# Calculate percentage
# Usage: calc_percentage <part> <total>
calc_percentage() {
    local part="$1"
    local total="$2"
    if [[ "$total" -eq 0 ]]; then
        echo "0"
    else
        echo $(( (part * 100) / total ))
    fi
}

# Validate IP address format
# Usage: is_valid_ip <ip>
# Returns: 0 if valid, 1 otherwise
is_valid_ip() {
    local ip="$1"
    local IFS='.'
    local -a octets
    read -ra octets <<< "$ip"
    
    [[ ${#octets[@]} -eq 4 ]] || return 1
    
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        [[ "$octet" -ge 0 && "$octet" -le 255 ]] || return 1
    done
    return 0
}

# Validate port number
# Usage: is_valid_port <port>
# Returns: 0 if valid, 1 otherwise
is_valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [[ "$port" -ge 1 && "$port" -le 65535 ]]
}

# Get file permissions in octal format
# Usage: get_file_perms <file>
get_file_perms() {
    stat -c "%a" "$1" 2>/dev/null || stat -f "%Lp" "$1" 2>/dev/null
}

# Get file owner
# Usage: get_file_owner <file>
get_file_owner() {
    stat -c "%U" "$1" 2>/dev/null || stat -f "%Su" "$1" 2>/dev/null
}

# Get file group
# Usage: get_file_group <file>
get_file_group() {
    stat -c "%G" "$1" 2>/dev/null || stat -f "%Sg" "$1" 2>/dev/null
}

# Check if system is Linux
# Returns: 0 if Linux, 1 otherwise
is_linux() {
    [[ "$(uname)" == "Linux" ]]
}

# Get OS name
# Usage: get_os_name
get_os_name() {
    if [[ -f /etc/os-release ]]; then
        grep -E "^NAME=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"'
    elif [[ -f /etc/redhat-release ]]; then
        cat /etc/redhat-release 2>/dev/null
    else
        uname -o 2>/dev/null || echo "Unknown"
    fi
}

# Get kernel version
# Usage: get_kernel_version
get_kernel_version() {
    uname -r
}

# Get hostname
# Usage: get_hostname
get_hostname() {
    hostname 2>/dev/null || uname -n
}

# Create temporary directory with cleanup trap
# Usage: create_temp_dir <prefix>
# Output: path to temp directory
create_temp_dir() {
    local prefix="${1:-sys-sec-auditor}"
    local temp_dir
    temp_dir=$(mktemp -d -t "${prefix}.XXXXXXXXXX")
    echo "$temp_dir"
}

# Cleanup function for temp directories
# Usage: cleanup_temp <dir>
cleanup_temp() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        rm -rf "$dir"
        log_debug "Cleaned up temp directory: $dir"
    fi
}

# Array contains check
# Usage: array_contains <array_name> <value>
# Returns: 0 if contains, 1 otherwise
array_contains() {
    local -n arr="$1"
    local value="$2"
    for item in "${arr[@]}"; do
        [[ "$item" == "$value" ]] && return 0
    done
    return 1
}

# Sort array numerically
# Usage: sort_array <array_name>
sort_array() {
    local -n arr="$1"
    IFS=$'\n' arr=($(sort -n <<<"${arr[*]}")); unset IFS
}

# Unique array elements
# Usage: unique_array <array_name>
unique_array() {
    local -n arr="$1"
    IFS=$'\n' arr=($(printf '%s\n' "${arr[@]}" | sort -u)); unset IFS
}
