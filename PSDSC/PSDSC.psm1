function Get-PsDscBasePath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $Script:PsDscBasePath
}

function Set-PsDscBasePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path
    )

    if (Test-Path -Path $Path) {
        $Script:PsDscBasePath = $Path
        Build-PsDscPaths
    
    } else {
        Write-Error ('[{0}] The specified path does not exist: <{1}>' -f $MyInvocation.MyCommand, $Path)
    }
}

function Build-PsDscPaths {
    $Script:PsDscNodePath   = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Node'
    $Script:PsDscCertPath   = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Cert'
    $Script:PsDscCredPath   = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Cred'
    $Script:PsDscOutputPath = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Output'
}

. (Join-Path -Path $PSScriptRoot -ChildPath 'Debugging.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Bootstrapping.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Authoring.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Architecture.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Shell.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Troubleshooting.ps1')

Set-PsDscBasePath -Path (Get-Item -Path $MyInvocation.ScriptName).Directory.FullName