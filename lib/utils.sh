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

# ============================================================================
# CONFIGURATION FILE SUPPORT
# ============================================================================

# Default configuration values
declare -A CONFIG_DEFAULTS=(
    ["DEBUG_ENABLED"]="false"
    ["QUIET_MODE"]="false"
    ["NO_COLOR"]="false"
    ["REQUIRE_ROOT"]="false"
    ["REPORT_FORMAT"]=""
    ["OUTPUT_FILE"]=""
    ["SPECIFIC_CHECK"]=""
    ["REPORT_DIR"]="/tmp/sys-sec-auditor-reports"
    ["LOG_LEVEL"]="INFO"
    ["MAX_FINDINGS"]="1000"
    ["EXCLUDE_CHECKS"]=""
    ["INCLUDE_CHECKS"]=""
)

# Global config array
declare -A CONFIG=()

# Load configuration from file
# Usage: load_config <config_file>
# Returns: 0 on success, 1 on error
load_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        log_error "Config file not found: $config_file"
        return 1
    fi

    if [[ ! -r "$config_file" ]]; then
        log_error "Config file not readable: $config_file"
        return 1
    fi

    log_debug "Loading config from: $config_file"

    local line_num=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_num++))

        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Remove leading/trailing whitespace
        line=$(trim "$line")

        # Parse KEY=VALUE format
        if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"

            # Remove surrounding quotes if present
            value=$(echo "$value" | sed -e 's/^["'"'"']//' -e 's/["'"'"']$//')

            CONFIG["$key"]="$value"
            log_debug "Config: $key = $value"
        else
            log_warn "Invalid config line $line_num: $line"
        fi
    done < "$config_file"

    log_debug "Config loaded successfully"
    return 0
}

# Get configuration value with default fallback
# Usage: get_config <key> [default]
get_config() {
    local key="$1"
    local default="${2:-}"

    # Check if key exists in CONFIG array
    if [[ -v CONFIG["$key"] ]]; then
        echo "${CONFIG[$key]}"
    # Check if key exists in CONFIG_DEFAULTS array
    elif [[ -v CONFIG_DEFAULTS["$key"] ]]; then
        echo "${CONFIG_DEFAULTS[$key]}"
    else
        echo "$default"
    fi
}

# Set configuration value
# Usage: set_config <key> <value>
set_config() {
    local key="$1"
    local value="$2"
    CONFIG["$key"]="$value"
}

# Check if config key exists
# Usage: has_config <key>
has_config() {
    local key="$1"
    [[ -n "${CONFIG[$key]+isset}" ]]
}

# Get all config keys
# Usage: get_config_keys
get_config_keys() {
    for key in "${!CONFIG[@]}"; do
        echo "$key"
    done
}

# Export config to environment variables
# Usage: export_config
export_config() {
    for key in "${!CONFIG[@]}"; do
        export "$key"="${CONFIG[$key]}"
    done
}

# Reset configuration to defaults
# Usage: reset_config
reset_config() {
    CONFIG=()
    for key in "${!CONFIG_DEFAULTS[@]}"; do
        CONFIG["$key"]="${CONFIG_DEFAULTS[$key]}"
    done
}

# Initialize config with defaults
# Usage: init_config
init_config() {
    reset_config
    log_debug "Configuration initialized with defaults"
}
