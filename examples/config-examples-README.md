# VEX Kernel Checker Configuration File Examples

This directory contains example configuration files for the VEX Kernel Checker.

## Files

- `sample-config.ini` - INI format configuration file
- `sample-config.json` - JSON format configuration file  
- `production-config.ini` - Example production configuration with all options
- `development-config.ini` - Example development configuration with verbose logging

## Usage

### Basic usage with configuration file
```bash
python3 vex-kernel-checker.py --config sample-config.ini
```

### Override specific options
```bash
python3 vex-kernel-checker.py --config sample-config.ini --verbose --reanalyse
```

### Create your own configuration file
```bash
# Create INI format
python3 vex-kernel-checker.py --create-config my-config.ini

# Create JSON format  
python3 vex-kernel-checker.py --create-config my-config.json --config-format json
```

## Configuration Format

### INI Format
```ini
[vex-kernel-checker]
vex_file = /path/to/vex-file.json
kernel_config = /path/to/.config
kernel_source = /path/to/kernel/source
api_key = your-api-key
verbose = true
```

### JSON Format
```json
{
  "vex_file": "/path/to/vex-file.json",
  "kernel_config": "/path/to/.config",
  "kernel_source": "/path/to/kernel/source",
  "api_key": "your-api-key",
  "verbose": true
}
```

## Tips

1. **Security**: Store API keys securely and consider using environment variables
2. **Paths**: Use absolute paths for better reliability
3. **Override**: Command-line arguments always override configuration file settings
4. **Format**: Choose the format that best fits your workflow (INI is more human-readable, JSON is more structured)
