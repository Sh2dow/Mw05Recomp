#!/usr/bin/env python3
"""Query IDA Pro API to get main thread decompilation."""

import requests
from pathlib import Path

def query_ida(address):
    """Query IDA Pro API for decompilation at given address."""
    url = f"http://127.0.0.1:5050/decompile?ea={address}"
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text
    except Exception as e:
        print(f"ERROR querying IDA: {e}")
        return None

def main():
    """Query main thread function."""
    # Main thread function
    address = "0x8262E9A0"
    print(f"Querying IDA for main thread function at {address}...")
    
    result = query_ida(address)
    if result:
        output_file = Path(f"traces/ida_main_thread_{address}.txt")
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"Saved to {output_file}")
        
        # Print first 100 lines
        lines = result.split("\n")
        print("\nFirst 100 lines:")
        print("\n".join(lines[:100]))
    else:
        print("Failed to query IDA")

if __name__ == "__main__":
    main()

