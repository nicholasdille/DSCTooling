if(-Not (Test-Path -Path $PSDSC_BasePath)) {
    Write-Error 'Variable <PSDSC_BasePath> is not defined. Aborting'
    throw
}

$PSDSC_DataFile       = Join-Path -Path $PSDSC_BasePath -ChildPath "ConfigurationData.ps1"
$PSDSC_FunctionsFile  = Join-Path -Path $PSDSC_BasePath -ChildPath "Functions.ps1"
$PSDSC_ConfigFile     = Join-Path -Path $PSDSC_BasePath -ChildPath "Configuration.psm1"
$PSDSC_OutputPath     = Join-Path -Path $PSDSC_BasePath -ChildPath "Output"