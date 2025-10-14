$matches = Select-String -Path "Mw05RecompLib/ppc/ppc_recomp.*.cpp" -Pattern "828F1F98" -SimpleMatch
foreach ($m in $matches) {
    Write-Host "$($m.Filename):$($m.LineNumber)"
}

