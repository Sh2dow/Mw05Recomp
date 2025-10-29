import urllib.request
import json

# Search for functions related to game state
keywords = ['state', 'mode', 'phase', 'stage', 'init', 'load', 'ready', 'start', 'begin', 'active', 'run']

r = urllib.request.urlopen('http://127.0.0.1:5050/functions?mode=fast&filter=&limit=10000')
data = json.loads(r.read())

funcs = []
for f in data['functions']:
    name_lower = f['name'].lower()
    if any(kw in name_lower for kw in keywords):
        funcs.append(f)

print(f"Found {len(funcs)} potential state-related functions:")
for f in funcs[:100]:
    print(f"{f['start_ea']} {f['name']}")

