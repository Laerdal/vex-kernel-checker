#!/usr/bin/env python3
"""
Fix test materials to comply with CycloneDX 1.5 specification.

This script updates all test JSON files to ensure:
1. response field is always an array, not a string
2. proper JSON formatting with separators=(', ', ' : ')
3. ensure_ascii=False for Unicode preservation
4. no trailing spaces
"""

import json
import os
from pathlib import Path


def fix_vex_response_fields(data):
    """Recursively fix response fields in VEX data structure."""
    if isinstance(data, dict):
        # If this dict has a 'response' key with a string value, convert to array
        if 'response' in data and isinstance(data['response'], str):
            data['response'] = [data['response']]
        
        # Recursively process all dict values
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                fix_vex_response_fields(value)
    
    elif isinstance(data, list):
        # Recursively process all list items
        for item in data:
            if isinstance(item, (dict, list)):
                fix_vex_response_fields(item)
    
    return data


def save_vex_file(vex_data, file_path):
    """Save VEX file with proper formatting."""
    with open(file_path, 'w', encoding='utf-8') as f:
        json_str = json.dumps(vex_data, indent=2, separators=(', ', ' : '), ensure_ascii=False)
        json_str = '\n'.join(line.rstrip() for line in json_str.split('\n'))
        f.write(json_str)
        f.write('\n')


def process_json_file(file_path):
    """Process a single JSON file."""
    print(f"Processing: {file_path}")
    
    try:
        # Read the JSON file
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Check if it has vulnerabilities (VEX format)
        if 'vulnerabilities' in data:
            original_json = json.dumps(data, sort_keys=True)
            
            # Fix response fields
            data = fix_vex_response_fields(data)
            
            modified_json = json.dumps(data, sort_keys=True)
            
            # Only save if changes were made
            if original_json != modified_json:
                save_vex_file(data, file_path)
                print(f"  ✓ Updated: {file_path}")
                return True
            else:
                print(f"  - No changes needed: {file_path}")
                return False
        else:
            print(f"  - Not a VEX file: {file_path}")
            return False
            
    except json.JSONDecodeError as e:
        print(f"  ✗ JSON decode error in {file_path}: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Error processing {file_path}: {e}")
        return False


def main():
    """Process all JSON files in examples directory."""
    script_dir = Path(__file__).parent
    project_dir = script_dir.parent
    examples_dir = project_dir / 'examples'
    
    print(f"Scanning for JSON files in: {examples_dir}")
    print("=" * 80)
    
    # Find all JSON files in examples directory
    json_files = list(examples_dir.glob('**/*.json'))
    
    print(f"Found {len(json_files)} JSON files\n")
    
    updated_count = 0
    skipped_count = 0
    error_count = 0
    
    for json_file in sorted(json_files):
        result = process_json_file(json_file)
        if result is True:
            updated_count += 1
        elif result is False:
            skipped_count += 1
        else:
            error_count += 1
    
    print("\n" + "=" * 80)
    print("Summary:")
    print(f"  Updated: {updated_count}")
    print(f"  Skipped: {skipped_count}")
    print(f"  Errors:  {error_count}")
    print(f"  Total:   {len(json_files)}")


if __name__ == '__main__':
    main()
