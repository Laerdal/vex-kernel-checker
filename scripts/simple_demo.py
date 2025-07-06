#!/usr/bin/env python3
"""
Simple demo showing the configuration filtering improvement.
"""

def demo_config_filtering():
    print("=== VEX Kernel Checker Configuration Filtering Demo ===\n")
    
    # Example config options from a real analysis (similar to your test.json output)
    example_configs = [
        'CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN',
        'CONFIG_GCC_PLUGIN_RANDSTRUCT', 
        'CONFIG_LTO_CLANG',
        'CONFIG_LTO_CLANG_THIN',
        'CONFIG_CC_HAS_RETURN_THUNK',
        'CONFIG_HEADERS_INSTALL',
        'CONFIG_ARCH_SUPPORTS_SHADOW_CALL_STACK',
        'CONFIG_MCOUNT',
        'CONFIG_HAS_LTO_CLANG',
        'CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE_O3',
        'CONFIG_SHADOW_CALL_STACK',
        'CONFIG_STRIP_ASM_SYMS',
        'CONFIG_FTRACE_MCOUNT_USE_RECORDMCOUNT',
        'CONFIG_INIT_STACK_ALL_PATTERN',
        'CONFIG_SUPERH',
        'CONFIG_CFI_CLANG',
        'CONFIG_RETHUNK',
        'CONFIG_EXPERT',
        'CONFIG_FRAME_WARN',
        'CONFIG_FUNCTION_GRAPH_TRACER',
        'CONFIG_DEBUG_INFO_BTF',
        # Mixed in some actually relevant options
        'CONFIG_NET',
        'CONFIG_USB',
        'CONFIG_DRM_TTM_HELPER',
        'CONFIG_MACSEC'
    ]
    
    # Define filtering rules
    irrelevant_prefixes = [
        'CONFIG_CC_',
        'CONFIG_GCC_',
        'CONFIG_LTO_',
        'CONFIG_CFI_',
        'CONFIG_DEBUG_',
        'CONFIG_FTRACE_',
        'CONFIG_FUNCTION_',
        'CONFIG_FRAME_',
        'CONFIG_STRIP_',
        'CONFIG_INIT_STACK_',
        'CONFIG_SHADOW_CALL_',
        'CONFIG_HEADERS_',
        'CONFIG_HAVE_',
        'CONFIG_AS_',
        'CONFIG_LD_'
    ]
    
    irrelevant_specific = [
        'CONFIG_EXPERT',
        'CONFIG_SUPERH',
        'CONFIG_UML',
        'CONFIG_MCOUNT',
        'CONFIG_RETHUNK',
        'CONFIG_RETPOLINE',
        'CONFIG_ARCH_SUPPORTS_SHADOW_CALL_STACK',
        'CONFIG_HAS_LTO_CLANG'
    ]
    
    # Filter the options
    relevant_options = []
    for option in example_configs:
        # Skip if matches irrelevant prefix
        if any(option.startswith(prefix) for prefix in irrelevant_prefixes):
            continue
        # Skip if in specific irrelevant list
        if option in irrelevant_specific:
            continue
        # Keep it
        relevant_options.append(option)
    
    # Show results
    print("BEFORE (original verbose output):")
    print(f"\"Required configuration options not enabled: {', '.join(example_configs)}\"")
    print(f"Length: {len(', '.join(example_configs))} characters")
    print(f"Count: {len(example_configs)} options")
    
    print("\nAFTER (filtered output):")
    print(f"\"Required configuration options not enabled: {', '.join(relevant_options)}\"")
    print(f"Length: {len(', '.join(relevant_options))} characters")
    print(f"Count: {len(relevant_options)} options")
    
    # Calculate improvement
    reduction_count = len(example_configs) - len(relevant_options)
    reduction_percent = (reduction_count / len(example_configs)) * 100
    
    print(f"\nIMPROVEMENT:")
    print(f"- Reduced by {reduction_count} options ({reduction_percent:.1f}%)")
    print(f"- Much more readable and focused on actual functional requirements")
    print(f"- Eliminates build-time and debugging options that don't affect vulnerability")

if __name__ == "__main__":
    demo_config_filtering()
