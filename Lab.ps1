$DataFile       = Join-Path $PSScriptRoot "ConfigurationData.psd1"
$FunctionsFile  = Join-Path $PSScriptRoot "Functions.ps1"
$ConfigFile     = Join-Path $PSScriptRoot "Configuration.psm1"
$OutputPath     = Join-Path $PSScriptRoot "Output"

. $FunctionsFile
. $DataFile
Import-Module $ConfigFile

if (-Not (Test-Path -Path "$OutputPath")) {
    New-Item -ItemType Directory -Path "$OutputPath"
}
Get-ChildItem "$OutputPath" | foreach {
    Remove-Item -Path "$($_.FullName)" -Force
}

$Params = @{OutputPath = "$OutputPath"; ConfigurationData = "$DataFile"}
Write-Verbose 'LabConfiguration'
LabConfiguration @Params

New-DscCheckSum -ConfigurationPath $OutputPath
Get-ChildItem -Path "$OutputPath" | where { $_.Name -imatch '^(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\.mof(\.checksum)?$' } | foreach {
    Copy-Item -Path "$($_.FullName)" -Destination "\\hv-04\c`$\Program Files\WindowsPowershell\DscService\Configuration" -Force
}
