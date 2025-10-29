import urllib.request
import json

# Search for functions that might write PM4 commands
keywords = ['draw', 'prim', 'batch', 'submit', 'command', 'packet', 'pm4', 'gpu', 'gfx']

r = urllib.request.urlopen('http://127.0.0.1:5050/functions?mode=fast&filter=&limit=10000')
data = json.loads(r.read())

funcs = []
for f in data['functions']:
    name_lower = f['name'].lower()
    if any(kw in name_lower for kw in keywords):
        funcs.append(f)

print(f"Found {len(funcs)} potential PM4 writer functions:")
for f in funcs[:100]:
    print(f"{f['start_ea']} {f['name']}")

