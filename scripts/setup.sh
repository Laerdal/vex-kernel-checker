#!/bin/bash

# VEX Kernel Checker Setup Script
# This script helps set up the environment for VEX Kernel Checker

set -e

echo "🔧 VEX Kernel Checker Setup"
echo "============================"

# Check Python version
python_version=$(python3 --version 2>&1 | grep -o '[0-9]\+\.[0-9]\+' | head -1)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✅ Python $python_version detected (>= $required_version required)"
else
    echo "❌ Python $python_version is too old. Please install Python >= $required_version"
    exit 1
fi

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Check if Edge browser is installed
if command -v microsoft-edge-stable >/dev/null 2>&1 || command -v microsoft-edge >/dev/null 2>&1; then
    echo "✅ Microsoft Edge browser detected"
else
    echo "⚠️  Microsoft Edge browser not found"
    echo "   For full patch checking functionality, please install Microsoft Edge:"
    echo "   https://www.microsoft.com/en-us/edge"
fi

# Create example directory
mkdir -p examples
if [ ! -f examples/sample-vex.json ]; then
    cat > examples/sample-vex.json << 'EOF'
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-52340",
      "details": "IPv6 implementation denial of service vulnerability"
    },
    {
      "id": "CVE-2023-52339", 
      "details": "Another example vulnerability"
    }
  ]
}
EOF
    echo "✅ Created example VEX file: examples/sample-vex.json"
fi

# Test basic functionality
echo ""
echo "🧪 Testing basic functionality..."
if python3 vex-kernel-checker.py --help >/dev/null 2>&1; then
    echo "✅ VEX Kernel Checker script is working"
else
    echo "❌ Error running VEX Kernel Checker script"
    exit 1
fi

# Check for kernel config and source
if [ -f "/boot/config-$(uname -r)" ]; then
    echo "✅ Kernel config found: /boot/config-$(uname -r)"
else
    echo "⚠️  Kernel config not found at /boot/config-$(uname -r)"
fi

if [ -d "/lib/modules/$(uname -r)/build" ]; then
    echo "✅ Kernel source found: /lib/modules/$(uname -r)/build"
else
    echo "⚠️  Kernel source not found at /lib/modules/$(uname -r)/build"
    echo "   You may need to install kernel headers: sudo apt-get install linux-headers-$(uname -r)"
fi

echo ""
echo "🎉 Setup completed!"
echo ""
echo "Next steps:"
echo "1. For basic config-only analysis:"
echo "   python3 vex-kernel-checker.py --vex-file examples/sample-vex.json --kernel-config /boot/config-\$(uname -r) --kernel-source /lib/modules/\$(uname -r)/build"
echo ""
echo "2. For full patch checking, obtain:"
echo "   - NVD API key: https://nvd.nist.gov/developers/request-an-api-key"
echo "   - Edge WebDriver: https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/"
echo ""
echo "3. Run with patch checking:"
echo "   python3 vex-kernel-checker.py --vex-file examples/sample-vex.json --kernel-config /boot/config-\$(uname -r) --kernel-source /lib/modules/\$(uname -r)/build --api-key YOUR_API_KEY --edge-driver /path/to/msedgedriver"
