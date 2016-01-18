Invoke-Pester -Script "$PSScriptRoot\ConfigurationData.Tests.ps1"

. "$PSScriptRoot\ConfigurationData.ps1"
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'MasterConfiguration.psm1') -Force
MasterConfiguration -ConfigurationData $ConfigurationData -OutputPath "$PSScriptRoot" | Out-Null