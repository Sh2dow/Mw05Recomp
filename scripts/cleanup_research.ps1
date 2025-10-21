param()
$ErrorActionPreference='Stop'
$root = Join-Path -Path (Get-Location) -ChildPath 'docs/research'
$arch = Join-Path $root 'archive'
if (!(Test-Path $arch)) { New-Item -ItemType Directory -Path $arch | Out-Null }
$skip = @('README.md','INDEX.md')
Get-ChildItem -Path $root -File -Filter '*.md' | Where-Object { $skip -notcontains $_.Name } | ForEach-Object {
    $dst = Join-Path $arch $_.Name
    if (Test-Path $dst) {
        & git rm -f -- $_.FullName
    } else {
        & git mv -f -- $_.FullName $dst
    }
}
Write-Host 'Cleanup forced complete.'

