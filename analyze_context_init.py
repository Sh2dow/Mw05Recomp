#!/usr/bin/env python3
"""
Analyze context initialization for Thread #2.
Compare Xenia (working) vs our implementation (broken).
"""

import re

def analyze_xenia():
    """Analyze Xenia log to find context initialization."""
    print("=" * 80)
    print("XENIA ANALYSIS: Thread #2 Context Initialization")
    print("=" * 80)
    
    # Thread #2 created at line 9535 with ctx=0x701EFAF0
    # Event F8000014 created at line 9343
    # Thread #1 (F800000C) creates both
    
    print("\nKey Events in Xenia:")
    print("  Line 9343: Thread #1 (F800000C) creates Event F8000014")
    print("  Line 9535: Thread #1 (F800000C) creates Thread #2 with ctx=0x701EFAF0")
    print("  Line 9968: Thread #1 (F800000C) resumes Thread #2")
    print("  Line 16874: Thread #2 (F8000018) waits on Event F8000014")
    
    print("\nContext Structure at 0x701EFAF0 (inferred):")
    print("  +0x00 (state):    0x00000000 (initial)")
    print("  +0x04 (func_ptr): 0x82XXXXXX (valid worker function)")
    print("  +0x08 (context):  0xF8000014 (Event handle)")
    
    print("\nConclusion:")
    print("  - Context is allocated in heap (0x70000000 range)")
    print("  - Context is initialized BEFORE ExCreateThread is called")
    print("  - Initialization happens in guest code (not logged)")
    print("  - Thread #1 does the initialization")

def analyze_our_impl():
    """Analyze our implementation to find the problem."""
    print("\n" + "=" * 80)
    print("OUR IMPLEMENTATION: Thread #2 Context Initialization")
    print("=" * 80)
    
    print("\nKey Events in Our Implementation:")
    print("  Thread #2 created with ctx=0x00120E10")
    print("  Thread #2 resumed")
    print("  Thread #2 executes with r3=0x00120E10")
    print("  Thread #2 completes immediately")
    
    print("\nContext Structure at 0x00120E10 (actual):")
    print("  +0x00 (state):    0x00000000 (OK)")
    print("  +0x04 (func_ptr): 0xE0348182 (GARBAGE!)")
    print("  +0x08 (context):  0x00000000 (OK)")
    
    print("\nProblem:")
    print("  - Context is in XEX data section (0x00100000 range)")
    print("  - Context contains GARBAGE (not initialized)")
    print("  - Game code that initializes context is NOT executing")
    
    print("\nAddress Analysis:")
    print("  Xenia:  0x701EFAF0 (heap, 0x70000000 range)")
    print("  Ours:   0x00120E10 (XEX data, 0x00100000 range)")
    print("  -> Different memory regions!")

def find_solution():
    """Propose solutions."""
    print("\n" + "=" * 80)
    print("SOLUTION PROPOSALS")
    print("=" * 80)
    
    print("\n1. Find the function that initializes the context:")
    print("   - Search for code that writes to offset +4 of a structure")
    print("   - Look for code that stores a function pointer (0x82XXXXXX)")
    print("   - Check if this code is being executed in our implementation")
    
    print("\n2. Check if context is allocated dynamically:")
    print("   - In Xenia, ctx=0x701EFAF0 (heap)")
    print("   - In ours, ctx=0x00120E10 (static/global)")
    print("   - Maybe the allocation function is not working?")
    
    print("\n3. Trace Thread #1 execution:")
    print("   - Add logging to see what Thread #1 does")
    print("   - Check if Thread #1 calls the initialization function")
    print("   - Compare with Xenia's Thread #1 execution")
    
    print("\n4. Manual workaround (temporary):")
    print("   - Initialize the context structure manually in ExCreateThread")
    print("   - Set func_ptr to a valid worker function address")
    print("   - Set context to Event handle")
    
    print("\n5. Check if there's a missing kernel function:")
    print("   - Maybe there's a kernel function that initializes contexts")
    print("   - Check if it's implemented and being called")

def main():
    analyze_xenia()
    analyze_our_impl()
    find_solution()
    
    print("\n" + "=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    print("\n1. Add memory write logging to see if context is being initialized")
    print("2. Check if address 0x00120E10 is ever written to")
    print("3. Find what function should write to 0x00120E10 + 4")
    print("4. Verify that function is being called")
    print("5. If not, find why it's not being called")

if __name__ == '__main__':
    main()

