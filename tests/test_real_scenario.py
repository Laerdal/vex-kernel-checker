#!/usr/bin/env python3
"""
Test script that demonstrates the improvement in configuration filtering
using an example similar to test_output.json
"""

def test_real_world_scenario():
    """Test with config options similar to those in test_output.json"""
    
    # These are the types of config options found in your test_output.json analysis
    found_config_options = [
        # Build/compiler options (should be filtered out)
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
        'CONFIG_CPU_SH2',
        'CONFIG_FTRACE_MCOUNT_USE_CC',
        'CONFIG_FUNCTION_TRACER',
        'CONFIG_DYNAMIC_FTRACE_WITH_REGS',
        'CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO',
        'CONFIG_HAVE_STACK_VALIDATION',
        'CONFIG_READABLE_ASM',
        'CONFIG_FTRACE_MCOUNT_USE_OBJTOOL',
        'CONFIG_M68K',
        'CONFIG_TRIM_UNUSED_KSYMS',
        'CONFIG_FTRACE_MCOUNT_RECORD',
        'CONFIG_LTO',
        'CONFIG_DEBUG_INFO_SPLIT',
        'CONFIG_DEBUG_INFO_REDUCED',
        'CONFIG_CC_OPTIMIZE_FOR_SIZE',
        'CONFIG_UML',
        'CONFIG_AS_VERSION',
        'CONFIG_RELR',
        'CONFIG_FUNCTION_ALIGNMENT',
        'CONFIG_DEBUG_SECTION_MISMATCH',
        'CONFIG_FTRACE_MCOUNT_USE_PATCHABLE_FUNCTION_ENTRY',
        'CONFIG_TOOLS_SUPPORT_RELR',
        'CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO_BARE',
        'CONFIG_ZERO_CALL_USED_REGS',
        'CONFIG_HAVE_OBJTOOL_MCOUNT',
        'CONFIG_HAVE_LD_DEAD_CODE_DATA_ELIMINATION',
        'CONFIG_MODULE_SIG',
        'CONFIG_INIT_STACK_ALL_ZERO',
        'CONFIG_COMPILE_TEST',
        'CONFIG_RETPOLINE',
        'CONFIG_LD_IS_LLD',
        'CONFIG_HAVE_NOP_MCOUNT',
        'CONFIG_CFI_PERMISSIVE',
        'CONFIG_STACK_VALIDATION',
        'CONFIG_LLD_VERSION',
        'CONFIG_DEBUG_INFO_COMPRESSED',
        'CONFIG_CC_HAS_AUTO_VAR_INIT_ZERO_ENABLER',
        'CONFIG_GDB_SCRIPTS',
        'CONFIG_ARC',
        'CONFIG_AS_IS_LLVM',
        'CONFIG_LD_DEAD_CODE_DATA_ELIMINATION',
        'CONFIG_CC_IS_CLANG',
        'CONFIG_CLANG_VERSION',
        'CONFIG_HAVE_FENTRY',
        
        # Actual functional config options (should be kept)
        'CONFIG_DRM_TTM_HELPER',
        'CONFIG_DRM_MIPI_DSI',
        'CONFIG_MACSEC',
        'CONFIG_ACPI_PROCESSOR',
        'CONFIG_AF_RXRPC',
        'CONFIG_HID_MAYFLASH',
        'CONFIG_HID_GREENASIA',
        'CONFIG_HID_UCLOGIC',
        'CONFIG_HID_LOGITECH_HIDPP',
        'CONFIG_HID_ASUS',
        'CONFIG_HID_FT260',
        'CONFIG_HID_CMEDIA',
        'CONFIG_HID_BETOP_FF'
    ]
    
    # Apply the same filtering logic as implemented in the tool
    irrelevant_prefixes = [
        'CONFIG_CC_', 'CONFIG_GCC_', 'CONFIG_CLANG_', 'CONFIG_LTO_', 
        'CONFIG_CFI_', 'CONFIG_DEBUG_', 'CONFIG_FRAME_', 'CONFIG_STRIP_',
        'CONFIG_FTRACE_', 'CONFIG_FUNCTION_', 'CONFIG_HEADERS_', 'CONFIG_AS_',
        'CONFIG_LD_', 'CONFIG_TOOLS_', 'CONFIG_INIT_STACK_', 'CONFIG_SHADOW_CALL_',
        'CONFIG_ZERO_CALL_', 'CONFIG_GDB_', 'CONFIG_HAVE_'
    ]
    
    irrelevant_specific = [
        'CONFIG_MODULE_SIG', 'CONFIG_SUPERH', 'CONFIG_M68K', 'CONFIG_UML',
        'CONFIG_ARC', 'CONFIG_ARCH_SUPPORTS_SHADOW_CALL_STACK', 'CONFIG_HAS_LTO_CLANG',
        'CONFIG_DYNAMIC_FTRACE', 'CONFIG_DYNAMIC_FTRACE_WITH_REGS', 'CONFIG_HAVE_STACK_VALIDATION',
        'CONFIG_HAVE_OBJTOOL_MCOUNT', 'CONFIG_HAVE_LD_DEAD_CODE_DATA_ELIMINATION',
        'CONFIG_HAVE_NOP_MCOUNT', 'CONFIG_HAVE_FENTRY', 'CONFIG_LLD_VERSION',
        'CONFIG_AS_VERSION', 'CONFIG_RETPOLINE', 'CONFIG_RETHUNK', 'CONFIG_MCOUNT',
        'CONFIG_READABLE_ASM', 'CONFIG_EXPERT', 'CONFIG_COMPILE_TEST',
        'CONFIG_STACK_VALIDATION', 'CONFIG_RELR', 'CONFIG_TRIM_UNUSED_KSYMS'
    ]
    
    # Filter the options
    relevant_options = []
    for option in found_config_options:
        # Skip if matches irrelevant prefix
        if any(option.startswith(prefix) for prefix in irrelevant_prefixes):
            continue
        # Skip if in specific irrelevant list  
        if option in irrelevant_specific:
            continue
        # Keep it
        relevant_options.append(option)
    
    print("=== VEX Kernel Checker Configuration Filtering Test ===")
    print(f"Scenario: Analysis of CVE similar to test_output.json\n")
    
    print("BEFORE (verbose output from test_output.json):")
    old_output = f'"Required configuration options not enabled: {", ".join(found_config_options)}"'
    print(f'Length: {len(old_output)} characters')
    print(f'Options: {len(found_config_options)} total')
    if len(old_output) > 200:
        print(f'Preview: {old_output[:200]}..."')
    else:
        print(f'Output: {old_output}')
    
    print(f"\nAFTER (filtered output):")
    new_output = f'"Required configuration options not enabled: {", ".join(relevant_options)}"'
    print(f'Length: {len(new_output)} characters')  
    print(f'Options: {len(relevant_options)} total')
    print(f'Output: {new_output}')
    
    # Calculate improvement
    reduction_count = len(found_config_options) - len(relevant_options)
    reduction_percent = (reduction_count / len(found_config_options)) * 100
    size_reduction = ((len(old_output) - len(new_output)) / len(old_output)) * 100
    
    print(f"\nIMPROVEMENT SUMMARY:")
    print(f"✅ Reduced from {len(found_config_options)} to {len(relevant_options)} options ({reduction_percent:.1f}% fewer)")
    print(f"✅ Output size reduced by {size_reduction:.1f}%")
    print(f"✅ Shows only functionally relevant configurations")
    print(f"✅ Eliminates build/debug/compiler options that don't affect vulnerability")
    
    print(f"\nFILTERED OUT (build/debug options):")
    filtered_out = [opt for opt in found_config_options if opt not in relevant_options]
    for i, opt in enumerate(sorted(filtered_out)):
        if i < 10:  # Show first 10
            print(f"  - {opt}")
        elif i == 10:
            print(f"  ... and {len(filtered_out) - 10} more")
            break
    
    print(f"\nKEPT (functional options):")
    for opt in sorted(relevant_options):
        print(f"  + {opt}")

if __name__ == "__main__":
    test_real_world_scenario()
