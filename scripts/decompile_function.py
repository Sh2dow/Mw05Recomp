#!/usr/bin/env python3
"""Decompile a function using IDA Pro HTTP server."""

import sys
import requests
import json

if len(sys.argv) < 2:
    print("Usage: python decompile_function.py <address>")
    sys.exit(1)

address = sys.argv[1]
url = f"http://127.0.0.1:5050/decompile?ea={address}"

try:
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    print(data['pseudocode'])
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)

