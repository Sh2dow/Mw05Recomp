#!/usr/bin/env python3
import os, time
ROOT = os.path.join('docs','research')
ARCH = os.path.join(ROOT,'archive')
OUTP = os.path.join(ROOT,'INDEX.md')
lines = []
lines.append('# Research Index')
lines.append('')
lines.append('## Consolidated (primary)')
lines.append('- [Rendering](consolidated/Rendering.md)')
lines.append('- [Threads & Synchronization](consolidated/Threads.md)')
lines.append('- [Status & Milestones](consolidated/Status.md)')
lines.append('- [Scripts & Tooling](consolidated/Tooling.md)')
lines.append('- [Logging & Traces](consolidated/Logging.md)')
lines.append('')
lines.append('## Archive by Date (most recent first)')
try:
    entries = [f for f in os.listdir(ARCH) if f.lower().endswith('.md')]
except FileNotFoundError:
    entries = []
entries.sort(key=lambda n: os.path.getmtime(os.path.join(ARCH,n)) if os.path.exists(os.path.join(ARCH,n)) else 0, reverse=True)
for name in entries:
    path = os.path.join(ARCH, name)
    try:
        t = os.path.getmtime(path)
        date = time.strftime('%Y-%m-%d', time.localtime(t))
    except Exception:
        date = '0000-00-00'
    base, _ = os.path.splitext(name)
    lines.append(f"- {date}  [{base}](archive/{name})")
os.makedirs(ROOT, exist_ok=True)
with open(OUTP, 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines)+'\n')
print(f'Wrote {OUTP} with {len(lines)} lines')

