function Get-PsDscBasePath {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER ComputerName
    XXX

    .PARAMETER CredentialName
    XXX

    .PARAMETER CimSession
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Write-Verbose ('[{0}] Returning PsDsc base path {1}' -f $MyInvocation.MyCommand, $Script:PsDscBasePath)
    $Script:PsDscBasePath
}

function Set-PsDscBasePath {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER ComputerName
    XXX

    .PARAMETER CredentialName
    XXX

    .PARAMETER CimSession
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path
    )

    Write-Verbose ('[{0}] Setting PsDsc base path' -f $MyInvocation.MyCommand)

    if (Test-Path -Path $Path) {
        Write-Verbose ('[{0}] The speficied path {1} exists' -f $MyInvocation.MyCommand, $Path)
        $Script:PsDscBasePath = $Path

        Write-Verbose ('[{0}] Creating PsDsc path variables from base path' -f $MyInvocation.MyCommand)
        Build-PsDscPaths
    
    } else {
        Write-Error ('[{0}] The specified path does not exist: <{1}>' -f $MyInvocation.MyCommand, $Path)
    }

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Build-PsDscPaths {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER ComputerName
    XXX

    .PARAMETER CredentialName
    XXX

    .PARAMETER CimSession
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    Write-Verbose ('[{0}] Building PsDsc paths' -f $MyInvocation.MyCommand)
    $Script:PsDscNodePath   = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Node'
    $Script:PsDscCertPath   = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Cert'
    $Script:PsDscCredPath   = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Cred'
    $Script:PsDscOutputPath = Join-Path -Path $Script:PsDscBasePath -ChildPath 'Output'
    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

$Files = @(
    'Debugging.ps1'
    'Bootstrapping.ps1'
    'Authoring.ps1'
    'Architecture.ps1'
    'Shell.ps1'
    'Troubleshooting.ps1'
)
foreach ($File in $Files) {
    Write-Verbose ('[{0}] Sourcing file {1}' -f $MyInvocation.MyCommand, $File)
    . (Join-Path -Path $PSScriptRoot -ChildPath $File)
}

Write-Verbose ('[{0}] Setting PsDsc base path' -f $MyInvocation.MyCommand)
Set-PsDscBasePath -Path (Get-Item -Path $MyInvocation.ScriptName).Directory.FullName