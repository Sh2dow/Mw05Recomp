#!/usr/bin/env python3
"""
Fetch IDA decompilation for a given address.
"""

import sys
import requests

def fetch_decompile(address, output_file=None):
    """Fetch decompilation from IDA Pro API."""
    url = f"http://127.0.0.1:5050/decompile?ea={address}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        content = response.text
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"Saved to {output_file}")
        else:
            print(content)
        
        return content
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching decompilation: {e}")
        return None

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python fetch_ida_decompile.py <address> [output_file]")
        print("Example: python fetch_ida_decompile.py 0x828508A8 traces/worker_thread.txt")
        sys.exit(1)
    
    address = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    fetch_decompile(address, output_file)

