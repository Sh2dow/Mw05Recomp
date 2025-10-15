$matches = Select-String -Path "Mw05RecompLib/ppc/ppc_recomp.*.cpp" -Pattern "sub_82813598" -SimpleMatch
foreach ($m in $matches) {
    Write-Host "$($m.Filename):$($m.LineNumber): $($m.Line.Trim())"
}

