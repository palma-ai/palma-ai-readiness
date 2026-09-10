# One-shot local scan; works in Windows PowerShell 5.1 and PowerShell 7.
$ErrorActionPreference = 'Stop'
$candidates = @(@('py', '-3.14'), @('py', '-3.13'), @('py', '-3.12'), @('py', '-3.11'), @('py', '-3'), @('python3'), @('python'))
if ($env:PALMA_PYTHON) { $candidates = @(,@($env:PALMA_PYTHON)) }
foreach ($candidate in $candidates) {
    $exe = $candidate[0]
    $pre = @($candidate | Select-Object -Skip 1)
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) { continue }
    try {
        $probe = & $exe @pre -I -S -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)' 2>$null
        if ("$probe".Trim() -ne '1') { continue }
    } catch { continue }
    & $exe @pre -I -S (Join-Path $PSScriptRoot 'palma-scan.py') run --open @args
    exit $LASTEXITCODE
}
[Console]::Error.WriteLine('Palma needs Python 3.11 or newer. No Python packages are required. Set PALMA_PYTHON to an existing executable if needed.')
exit 2
