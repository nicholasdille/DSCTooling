powershell -NoExit -Command {
    param([string]$PSDSC_BasePath)
    function prompt {'PS [psdsc]> '}
    . (Join-Path -Path $PSDSC_BasePath -ChildPath 'Variables.ps1')
    . $PSDSC_FunctionsFile
} -args $PSScriptRoot