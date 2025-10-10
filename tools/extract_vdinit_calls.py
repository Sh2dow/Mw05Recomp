#!/usr/bin/env python3
"""Extract VdInitializeEngines calls from trace log."""

import re
import sys

def main():
    trace_file = "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log"
    
    # Pattern: [HOST] import=HOST.VdInitializeEngines tid=XXXX lr=0xXXXXXXXX r3=0xXXXXXXXX r4=0xXXXXXXXX r5=0xXXXXXXXX r6=0xXXXXXXXX
    pattern = r'\[HOST\] import=HOST\.VdInitializeEngines tid=([0-9a-f]+) lr=0x([0-9A-F]+) r3=0x([0-9A-F]+) r4=0x([0-9A-F]+) r5=0x([0-9A-F]+) r6=0x([0-9A-F]+)'
    
    calls = []
    with open(trace_file, 'r') as f:
        for line in f:
            m = re.search(pattern, line)
            if m:
                tid, lr, r3, r4, r5, r6 = m.groups()
                calls.append({
                    'tid': tid,
                    'lr': lr,
                    'r3': r3,
                    'r4': r4,
                    'r5': r5,
                    'r6': r6
                })
    
    print(f"Found {len(calls)} VdInitializeEngines calls:")
    for i, call in enumerate(calls):
        print(f"  Call #{i+1}: tid={call['tid']} r3=0x{call['r3']} r4=0x{call['r4']} r5=0x{call['r5']} r6=0x{call['r6']}")
    
    # Find calls with non-zero r3 (callback)
    callback_calls = [c for c in calls if c['r3'] != '0']
    print(f"\nCalls with non-zero callback (r3): {len(callback_calls)}")
    for i, call in enumerate(callback_calls):
        print(f"  Call #{i+1}: tid={call['tid']} cb=0x{call['r3']} arg1=0x{call['r4']} arg2=0x{call['r5']} arg3=0x{call['r6']}")

if __name__ == '__main__':
    main()

