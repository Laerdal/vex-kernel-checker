#!/usr/bin/env python3
"""
Test GitHub-first patch fetching priority logic
"""

import re
from typing import List, Optional

def extract_patch_url_github_first(patch_urls: List[str], ignored_urls: set) -> Optional[str]:
    """Test version of extract_patch_url with GitHub priority."""
    if not patch_urls:
        return None
    
    def url_ignored(url: str) -> bool:
        return any(ignored_domain in url for ignored_domain in ignored_urls)
    
    # Prioritize GitHub URLs first (better API availability and reliability)
    for url in patch_urls:
        if url_ignored(url):
            continue
            
        if 'github.com' in url:
            return url
    
    # Then try kernel.org URLs
    for url in patch_urls:
        if url_ignored(url):
            continue
            
        if 'git.kernel.org' in url:
            return url
    
    # Fall back to any non-ignored URL
    for url in patch_urls:
        if not url_ignored(url):
            return url
    
    return None

def get_alternative_patch_urls_github_first(original_url: str) -> List[str]:
    """Test version of get_alternative_patch_urls with GitHub priority."""
    alternatives = []
    
    # Extract commit ID
    def extract_commit_id(url: str) -> Optional[str]:
        patterns = [
            r'github\.com/[^/]+/[^/]+/commit/([a-f0-9]{8,40})',
            r'git\.kernel\.org/.*[?&]id=([a-f0-9]{8,40})',
            r'git\.kernel\.org/stable/c/([a-f0-9]{8,40})',  # git.kernel.org/stable/c/COMMIT_ID
            r'git\.kernel\.org/.*/c/([a-f0-9]{8,40})',      # any git.kernel.org/*/c/COMMIT_ID format
        ]
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        return None
    
    commit_id = extract_commit_id(original_url)
    if not commit_id:
        return alternatives
    
    # Prioritize GitHub URLs first
    github_templates = [
        f"https://github.com/torvalds/linux/commit/{commit_id}.patch",
        f"https://github.com/torvalds/linux/commit/{commit_id}.diff",
        f"https://github.com/torvalds/linux/commit/{commit_id}",
    ]
    
    # Then kernel.org URLs
    kernel_org_templates = [
        f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit_id}",
        f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_id}",
    ]
    
    # Add original URL if not already included
    if original_url not in github_templates + kernel_org_templates:
        alternatives.append(original_url)
    
    # Add GitHub URLs first, then kernel.org URLs
    alternatives.extend(github_templates)
    alternatives.extend(kernel_org_templates)
    
    return alternatives

def test_github_priority():
    """Test the GitHub-first priority logic."""
    print("Testing GitHub-first patch URL priority...")
    print("=" * 50)
    
    # Test data: mixed URLs (like what NVD might return)
    test_urls = [
        "https://git.kernel.org/stable/c/6209319b2efdd8524691187ee99c40637558fa33",
        "https://github.com/torvalds/linux/commit/6209319b2efdd8524691187ee99c40637558fa33",
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6209319b2efdd8524691187ee99c40637558fa33",
        "https://lore.kernel.org/some-mailing-list/message-id",
    ]
    
    ignored_urls = {"https://example.com/ignore"}
    
    print("Input URLs:")
    for i, url in enumerate(test_urls, 1):
        domain = "GitHub" if "github.com" in url else ("kernel.org" if "kernel.org" in url else "Other")
        print(f"  {i}. [{domain}] {url}")
    
    # Test URL selection
    selected_url = extract_patch_url_github_first(test_urls, ignored_urls)
    print(f"\nSelected URL (should be GitHub): {selected_url}")
    
    if selected_url and "github.com" in selected_url:
        print("✅ PASS: GitHub URL correctly prioritized")
    else:
        print("❌ FAIL: GitHub URL not prioritized")
    
    # Test alternative URL generation
    print(f"\nTesting alternative URL generation for kernel.org URL:")
    kernel_url = test_urls[0]  # kernel.org URL
    alternatives = get_alternative_patch_urls_github_first(kernel_url)
    
    print(f"Original: {kernel_url}")
    print("Alternatives (GitHub should be first):")
    for i, alt_url in enumerate(alternatives, 1):
        domain = "GitHub" if "github.com" in alt_url else ("kernel.org" if "kernel.org" in alt_url else "Other")
        print(f"  {i}. [{domain}] {alt_url}")
    
    # Check if GitHub URLs come first (excluding the original URL)
    github_first = False
    first_non_original_is_github = False
    
    if len(alternatives) > 1:  # Skip original URL at index 0
        for i, url in enumerate(alternatives[1:], 1):  # Start from index 1
            if "github.com" in url:
                first_non_original_is_github = True
                github_first = True
                break
            elif "git.kernel.org" in url:
                break
    
    if github_first and first_non_original_is_github:
        print("✅ PASS: GitHub URLs prioritized in alternatives (after original)")
    elif github_first:
        print("✅ PASS: GitHub URLs found in alternatives")
    else:
        print("❌ FAIL: GitHub URLs not prioritized in alternatives")
    
    print("\n" + "=" * 50)
    print("GitHub-first priority logic verification complete!")

if __name__ == "__main__":
    test_github_priority()
