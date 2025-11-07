#!/usr/bin/env python3
"""
Simple demo showing how to use AI Assistant with vex-kernel-checker.

This demo shows:
1. How to initialize the AI Assistant
2. CVE relevance detection
3. Security mitigation suggestions
4. Batch analysis of multiple CVEs

Note: Requires OpenAI or Anthropic API key set in environment.
"""

import os
import sys

# Add parent directory to path to import vex_kernel_checker
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vex_kernel_checker import AIAssistant


def demo_cve_relevance():
    """Demonstrate CVE relevance detection."""
    print("=" * 80)
    print("Demo 1: CVE Relevance Detection")
    print("=" * 80)
    
    # Initialize AI assistant
    ai = AIAssistant(
        provider="openai",  # or "anthropic"
        api_key=os.getenv("OPENAI_API_KEY"),  # or ANTHROPIC_API_KEY
        model="gpt-4"  # or "claude-3-opus-20240229"
    )
    
    # Example CVE data
    cve_id = "CVE-2024-1234"
    description = "A buffer overflow vulnerability in the Linux kernel's USB driver allows local privilege escalation"
    kernel_config = {
        "CONFIG_USB": "y",
        "CONFIG_USB_STORAGE": "m",
        "CONFIG_SECURITY_SELINUX": "y"
    }
    
    # Analyze relevance
    result = ai.analyze_cve_relevance(
        cve_id=cve_id,
        description=description,
        kernel_config=kernel_config
    )
    
    print(f"\nCVE: {cve_id}")
    print(f"Affects kernel: {result['affects_kernel']}")
    print(f"Confidence: {result['confidence']:.0%}")
    print(f"\nReasoning:\n{result['reasoning']}")
    print(f"\nRelevant configs:\n{', '.join(result['relevant_configs'])}")


def demo_mitigation_suggestions():
    """Demonstrate security mitigation suggestions."""
    print("\n" + "=" * 80)
    print("Demo 2: Security Mitigation Suggestions")
    print("=" * 80)
    
    ai = AIAssistant(
        provider="openai",
        api_key=os.getenv("OPENAI_API_KEY"),
        model="gpt-4"
    )
    
    # Example vulnerability
    cve_id = "CVE-2024-5678"
    description = "Use-after-free in network stack allows remote code execution"
    current_config = {
        "CONFIG_NETWORKING": "y",
        "CONFIG_NET": "y",
        "CONFIG_INET": "y"
    }
    
    # Get mitigation suggestions
    result = ai.suggest_mitigation(
        cve_id=cve_id,
        description=description,
        current_config=current_config,
        patched=False
    )
    
    print(f"\nCVE: {cve_id}")
    print(f"Severity assessment: {result['severity']}")
    print(f"\nRecommended actions:")
    for i, action in enumerate(result['recommendations'], 1):
        print(f"{i}. {action}")
    
    print(f"\nConfiguration changes:")
    for config, value in result['config_changes'].items():
        print(f"  {config}={value}")
    
    print(f"\nWorkarounds:\n{result['workarounds']}")


def demo_batch_analysis():
    """Demonstrate batch CVE analysis."""
    print("\n" + "=" * 80)
    print("Demo 3: Batch CVE Analysis")
    print("=" * 80)
    
    ai = AIAssistant(
        provider="openai",
        api_key=os.getenv("OPENAI_API_KEY"),
        model="gpt-3.5-turbo",  # Faster model for batch processing
        rate_limit_delay=1.0  # Respect rate limits
    )
    
    # Multiple CVEs to analyze
    cves = [
        {
            "id": "CVE-2024-0001",
            "description": "Integer overflow in filesystem driver",
            "kernel_config": {"CONFIG_EXT4_FS": "y"}
        },
        {
            "id": "CVE-2024-0002",
            "description": "Race condition in memory management",
            "kernel_config": {"CONFIG_MEMORY_HOTPLUG": "y"}
        },
        {
            "id": "CVE-2024-0003",
            "description": "SQL injection in web application",
            "kernel_config": {"CONFIG_NET": "y"}
        }
    ]
    
    # Batch analyze
    results = ai.batch_analyze_cves(cves)
    
    print(f"\nAnalyzed {len(results)} CVEs:")
    for result in results:
        if result.get('error'):
            print(f"  {result['id']}: ERROR - {result['error']}")
        else:
            print(f"  {result['id']}: {'AFFECTS' if result['affects_kernel'] else 'NOT RELEVANT'} (confidence: {result['confidence']:.0%})")


def main():
    """Run all demos."""
    # Check for API key
    if not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
        print("ERROR: No API key found!")
        print("\nPlease set one of the following environment variables:")
        print("  export OPENAI_API_KEY='your-key-here'")
        print("  export ANTHROPIC_API_KEY='your-key-here'")
        print("\nSee docs/AI_ASSISTANT.md for setup instructions.")
        sys.exit(1)
    
    try:
        demo_cve_relevance()
        demo_mitigation_suggestions()
        demo_batch_analysis()
        
        print("\n" + "=" * 80)
        print("All demos completed successfully!")
        print("=" * 80)
        
    except ImportError as e:
        print(f"\nERROR: Missing AI libraries")
        print(f"Details: {e}")
        print("\nInstall with: pip install vex-kernel-checker[ai]")
        print("Or: pip install openai anthropic")
        sys.exit(1)
    except Exception as e:
        print(f"\nERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
