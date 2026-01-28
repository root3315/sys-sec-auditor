# sys-sec-auditor

A comprehensive bash-based system security audit tool for scanning vulnerabilities and misconfigurations on Linux systems.

## Features

- **File Permission Auditing**: Detect world-writable files, SUID/SGID binaries, and incorrect permissions on critical files
- **User Account Analysis**: Find accounts with empty passwords, unauthorized UID 0 accounts, and missing password expiration
- **Service Detection**: Identify listening services and insecure protocols (telnet, FTP, rsh)
- **Configuration Checks**: Audit kernel parameters, SSH configuration, and cron job security
- **Logging Verification**: Check logging daemon status and analyze failed login attempts
- **Multiple Report Formats**: Generate reports in text, JSON, CSV, or HTML format

## Installation

### Quick Install

```bash
# Clone or download the project
git clone <repository-url>
cd sys-sec-auditor

# Make the main script executable
chmod +x sys-sec-auditor

# Optionally install to system path
sudo cp sys-sec-auditor /usr/local/bin/
```

### Requirements

- Bash 4.0 or later
- Linux operating system
- Root privileges recommended for full audit coverage

## Usage

### Basic Usage

```bash
# Run a full security audit
./sys-sec-auditor

# Run with root privileges for complete coverage
sudo ./sys-sec-auditor
```

### Command Line Options

```
Options:
  -h, --help           Show help message
  -v, --version        Show version information
  -d, --debug          Enable debug output
  -q, --quiet          Suppress non-essential output
  -r, --report FORMAT  Generate report (text|json|csv|html)
  -o, --output FILE    Specify output file for report
  -c, --check NAME     Run specific check only
  -l, --list           List available checks
  --no-color           Disable colored output
  --root               Require root privileges
```

### Examples

```bash
# Run full audit with JSON report
./sys-sec-auditor --report json --output /tmp/audit.json

# Run specific security check
./sys-sec-auditor --check ssh_config

# Run with debug output
./sys-sec-auditor --debug

# List all available checks
./sys-sec-auditor --list

# Generate HTML report
./sys-sec-auditor --report html --output security_report.html
```

## Security Checks

### File Permissions

| Check | Description |
|-------|-------------|
| `world_writable` | Find world-writable files in sensitive directories |
| `suid_sgid` | Detect non-standard SUID/SGID binaries |
| `critical_perms` | Verify permissions on critical system files |

### User Accounts

| Check | Description |
|-------|-------------|
| `empty_passwords` | Detect accounts with empty passwords |
| `uid_zero` | Find non-root accounts with UID 0 |
| `password_aging` | Check password expiration policies |
| `locked_accounts` | List locked/disabled accounts |

### Services

| Check | Description |
|-------|-------------|
| `listening` | Identify services bound to all interfaces |
| `insecure_services` | Detect insecure services (telnet, FTP, etc.) |

### Configuration

| Check | Description |
|-------|-------------|
| `kernel_params` | Verify kernel security parameters |
| `ssh_config` | Audit SSH daemon configuration |
| `cron_jobs` | Check cron job security |

### Logging

| Check | Description |
|-------|-------------|
| `logging` | Verify logging configuration |
| `failed_logins` | Analyze failed login attempts |

### Software

| Check | Description |
|-------|-------------|
| `versions` | Check for pending updates |

## How It Works

### Architecture

```
sys-sec-auditor/
├── sys-sec-auditor    # Main entry point
├── lib/
│   ├── utils.sh       # Utility functions
│   ├── checks.sh      # Security check implementations
│   └── reporting.sh   # Report generation
├── tests/
│   └── test_auditor.sh # Test suite
└── README.md          # This file
```

### Execution Flow

1. **Initialization**: Parse command-line arguments and validate environment
2. **Module Loading**: Source utility, check, and reporting modules
3. **Check Execution**: Run security checks based on user input
4. **Finding Collection**: Store findings with severity levels
5. **Report Generation**: Output results in requested format

### Severity Levels

- **CRITICAL**: Immediate action required (e.g., empty passwords, unauthorized root accounts)
- **HIGH**: Should be addressed soon (e.g., world-writable files, insecure services)
- **MEDIUM**: Review and fix when possible (e.g., non-standard SUID binaries)
- **LOW**: Informational or minor issues (e.g., missing password expiration)

## Report Formats

### Text Format

Human-readable text report with formatted sections, suitable for terminal output or printing.

### JSON Format

Machine-readable format for integration with other tools and automated processing.

```json
{
  "report": {
    "type": "security_audit",
    "generated": "2024-01-15T10:30:00+0000"
  },
  "summary": {
    "total": 5,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "low": 1
  },
  "findings": [...]
}
```

### CSV Format

Spreadsheet-compatible format for analysis in Excel or similar tools.

### HTML Format

Styled HTML report suitable for sharing and presentation.

## Running Tests

```bash
# Make test script executable
chmod +x tests/test_auditor.sh

# Run all tests
./tests/test_auditor.sh

# Run with verbose output
./tests/test_auditor.sh --verbose
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success (no critical findings) |
| 1 | General error or critical findings detected |
| 2 | Root privileges required |
| 3 | Invalid option |

## Security Considerations

- Run with appropriate privileges for your environment
- Review findings before making system changes
- Some checks may produce false positives
- Always test in a non-production environment first

## Limitations

- Designed for Linux systems; may not work correctly on other Unix variants
- Some checks require root access for complete results
- Network-based checks are limited to local system information

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite
5. Submit a pull request

## License

This project is provided as-is for educational and security auditing purposes.

## Version History

- **1.0.0**: Initial release with core security checks and reporting
