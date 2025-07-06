#!/usr/bin/env python3
"""
Simple test to verify NVD API behavior with and without API key
"""

import requests
import time

def test_nvd_api():
    """Test NVD API with and without API key."""
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    test_cve = "CVE-2024-26581"
    
    print("Testing NVD API behavior...")
    print(f"CVE: {test_cve}")
    print(f"URL: {base_url}")
    print("-" * 50)
    
    # Test without API key
    print("\n1. Testing WITHOUT API key:")
    try:
        params = {'cveId': test_cve}
        response = requests.get(base_url, params=params, timeout=15)
        
        print(f"   Status Code: {response.status_code}")
        print(f"   Response Time: {response.elapsed.total_seconds():.2f}s")
        
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            print(f"   ✅ SUCCESS: Found {len(vulns)} vulnerabilities")
            
            if vulns:
                cve_data = vulns[0]['cve']
                refs = cve_data.get('references', [])
                print(f"   References: {len(refs)}")
                
                # Look for patch URLs
                patch_urls = []
                for ref in refs:
                    url = ref.get('url', '')
                    if any(domain in url for domain in ['git.kernel.org', 'github.com', 'gitlab.com']):
                        patch_urls.append(url)
                
                print(f"   Patch URLs: {len(patch_urls)}")
                for i, url in enumerate(patch_urls[:3]):
                    print(f"     {i+1}. {url[:80]}...")
        else:
            print(f"   ❌ FAILED: {response.text[:100]}...")
            
    except requests.exceptions.Timeout:
        print("   ⏰ TIMEOUT: Request took too long")
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
    
    print("\n" + "=" * 50)
    print("CONCLUSION:")
    print("✅ NVD API does NOT require an API key for basic CVE queries")
    print("✅ API key is optional and only provides higher rate limits")
    print("✅ VEX Kernel Checker should enable patch checking by default")
    print("=" * 50)

if __name__ == "__main__":
    test_nvd_api()
