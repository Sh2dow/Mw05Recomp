$content = Get-Content 'Mw05Recomp/kernel/imports.cpp' -Raw
$content = $content -replace 'g_userHeap\.Alloc\(([^,]+),\s*0x100\)', 'g_userHeap.Alloc($1)'
$content = $content -replace 'g_userHeap\.Alloc\(([^,]+),\s*4\)', 'g_userHeap.Alloc($1)'
$content = $content -replace 'g_userHeap\.Alloc\(([^,]+),\s*0x1000\)', 'g_userHeap.Alloc($1)'
$content = $content -replace 'g_userHeap\.Alloc\(([^,]+),\s*alignof\([^)]+\)\)', 'g_userHeap.Alloc($1)'
Set-Content 'Mw05Recomp/kernel/imports.cpp' -Value $content -NoNewline

