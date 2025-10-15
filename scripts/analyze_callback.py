import re

# Analyze the graphics callback function
with open('NfsMWEurope.xex.html', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Find the callback function at 0x825979A8
pattern = r'\.text:825979A8'
match = re.search(pattern, content)

if not match:
    print('Could not find callback function')
    exit(1)

# Extract the function (until next function or reasonable limit)
start = match.start()
# Look for next function
next_func = re.search(r'\.text:8259[0-9A-F]{4}\s+sub_8259[0-9A-F]{4}:', content[start+10:])
if next_func:
    end = start + 10 + next_func.start()
else:
    end = start + 5000

func_content = content[start:end]
lines = func_content.split('\n')

print('Graphics callback function (sub_825979A8):')
print('=' * 80)

# Clean and print, highlighting key instructions
for i, line in enumerate(lines[:200]):  # Increased to 200 lines
    clean = re.sub(r'<[^>]+>', '', line)
    if not clean.strip():
        continue

    # Highlight important instructions
    if '0x3CEC' in line:
        print(f' >>> {clean[:120]}')
    elif 'lwz' in line and 'r31' in line:
        print(f'  *  {clean[:120]}')
    elif 'bl ' in line:
        print(f'  -> {clean[:120]}')
    elif 'blr' in line:
        print(f' RET {clean[:120]}')
        # Don't break - there might be more code after
    else:
        print(f'     {clean[:120]}')

print('\n' + '=' * 80)
print('Analysis:')
print('=' * 80)

# Check for the load from 0x3CEC
if '0x3CEC' in func_content:
    print('[OK] Function loads from context+0x3CEC')

    # Check if it's checked for NULL
    if 'cmplwi' in func_content[:func_content.find('0x3CEC')+100]:
        print('[OK] Function checks if pointer is NULL before using it')
    else:
        print('[WARN] Function does NOT check for NULL')

    # Check if it's called
    if 'mtctr' in func_content[func_content.find('0x3CEC'):]:
        print('[OK] Function pointer is called via mtctr/bctrl')
    elif 'bl ' in func_content[func_content.find('0x3CEC'):]:
        print('[OK] Function is called via bl')
    else:
        print('[?] Function pointer usage unclear')
else:
    print('[WARN] No reference to context+0x3CEC found in first 200 lines')

