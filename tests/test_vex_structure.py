#!/usr/bin/env python3
"""
Quick test to verify patch URL extraction from VEX data
"""

import sys
import json

# Load test VEX data
with open('test_cve_with_patches.json', 'r') as f:
    vex_data = json.load(f)

print("=== VEX Data Structure Analysis ===")
print(f"VEX contains {len(vex_data['vulnerabilities'])} vulnerabilities")

for vuln in vex_data['vulnerabilities']:
    print(f"\nCVE: {vuln['id']}")
    print(f"Description: {vuln.get('description', 'N/A')}")
    
    if 'references' in vuln:
        print(f"References found: {len(vuln['references'])}")
        for i, ref in enumerate(vuln['references']):
            print(f"  Reference {i+1}:")
            print(f"    ID: {ref.get('id', 'N/A')}")
            if 'source' in ref:
                print(f"    Name: {ref['source'].get('name', 'N/A')}")
                print(f"    URL: {ref['source'].get('url', 'N/A')}")
            else:
                print(f"    URL: {ref.get('url', 'N/A')}")
    else:
        print("No references found")

print("\n=== Expected Patch URLs ===")
for vuln in vex_data['vulnerabilities']:
    if 'references' in vuln:
        for ref in vuln['references']:
            if 'source' in ref:
                url = ref['source'].get('url', '')
            else:
                url = ref.get('url', '')
            
            if any(keyword in url for keyword in ['git.kernel.org', 'github.com', 'commit', 'patch']):
                print(f"Potential patch URL: {url}")
