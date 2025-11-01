# Test worker threads with original recompiled code (disable workaround)
$env:MW05_SKIP_828508A8_BUG = "0"

# Run test
python scripts/auto_handle_messageboxes.py --duration 20

