# VEX Kernel Checker Examples

This directory contains example files and usage scenarios for the VEX Kernel Checker tool.

## Sample Files

### `sample-vex.json`
A basic VEX file with example vulnerabilities for testing the tool functionality.

### `sample-kernel-config`
An example kernel configuration file showing the format expected by the tool.

## Usage Examples

### Basic Configuration Analysis
```bash
python3 ../vex-kernel-checker.py \
  --vex-file sample-vex.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /lib/modules/$(uname -r)/build \
  --verbose
```

### Full Patch Checking Analysis
```bash
python3 ../vex-kernel-checker.py \
  --vex-file sample-vex.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /lib/modules/$(uname -r)/build \
  --api-key YOUR_NVD_API_KEY \
  --edge-driver /path/to/msedgedriver \
  --verbose
```

### Re-analyze Existing Results
```bash
python3 ../vex-kernel-checker.py \
  --vex-file sample-vex.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /lib/modules/$(uname -r)/build \
  --reanalyse \
  --output updated-sample-vex.json
```

### Process Single CVE
```bash
python3 ../vex-kernel-checker.py \
  --vex-file sample-vex.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /lib/modules/$(uname -r)/build \
  --cve-id CVE-2023-52340 \
  --verbose
```

### Performance Testing
```bash
python3 ../vex-kernel-checker.py \
  --vex-file sample-vex.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /lib/modules/$(uname -r)/build \
  --performance-stats \
  --clear-cache
```

## Expected Outputs

The tool will generate analysis results in the VEX file with structures like:

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-52340",
      "details": "IPv6 implementation denial of service vulnerability",
      "analysis": {
        "state": "under_investigation",
        "justification": "requires_configuration",
        "detail": "Manual review recommended...",
        "timestamp": "2025-07-05T16:05:52Z"
      }
    }
  ],
  "metadata": {
    "last_analysis": "2025-07-05T16:05:52Z",
    "processed_count": 1,
    "error_count": 0,
    "tool_version": "2.0",
    "analysis_method": "kernel_config_analysis"
  }
}
```
