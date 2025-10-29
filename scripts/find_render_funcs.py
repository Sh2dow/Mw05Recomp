import urllib.request
import json

r = urllib.request.urlopen('http://127.0.0.1:5050/functions?mode=fast&filter=&limit=5000')
data = json.loads(r.read())
funcs = [f for f in data['functions'] if any(x in f['name'].lower() for x in ['render', 'scene', 'world', 'camera', 'viewport'])]
for f in funcs[:50]:
    print(f"{f['start_ea']} {f['name']}")

