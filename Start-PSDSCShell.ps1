powershell -NoExit -Command {
    param([string]$PSDSC_BasePath)
    function prompt {'PS [psdsc]> '}
    Set-Location -Path $PSDSC_BasePath
    . .\Variables.ps1
    . $PSDSC_FunctionsFile
    Get-ChildItem $PSDSC_BasePath\Functions_*.ps1 | foreach { . .\$($_.Name) }
} -args $PSScriptRoot