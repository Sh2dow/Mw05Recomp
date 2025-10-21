#!/usr/bin/env python3
"""Fetch decompiled code from IDA Pro HTTP server."""

import requests
import sys

def fetch_decompile(address):
    """Fetch decompiled code for a function at the given address."""
    url = f"http://127.0.0.1:5050/decompile?ea={address}"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        data = response.json()
        return data.get('pseudocode', 'No pseudocode available')
    except Exception as e:
        return f"Error fetching decompiled code: {e}"

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python fetch_decompile.py <address>")
        sys.exit(1)
    
    address = sys.argv[1]
    pseudocode = fetch_decompile(address)
    
    # Save to file
    output_file = f"traces/sub_{address.replace('0x', '')}_decompile.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(pseudocode)
    
    print(f"Decompiled code saved to {output_file}")
    print("\nFirst 50 lines:")
    print('\n'.join(pseudocode.split('\n')[:50]))

