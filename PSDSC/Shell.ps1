function Assert-Path {
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

    Write-Verbose ('[{0}] Making sure that {1} exists' -f $MyInvocation.MyCommand, $Path)

    if (-Not (Test-Path -Path $Path)) {
        Write-Verbose ('[{0}] Creating path {1}' -f $MyInvocation.MyCommand, $Path)
        New-Item -ItemType Directory -Path $Path
    }

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Assert-OutputPath {
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
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath = $Script:PsDscOutputPath
    )

    Write-Verbose ('[{0}] Making sure that the output path {1} exists' -f $MyInvocation.MyCommand, $OutputPath)
    Assert-Path -Path $OutputPath
    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Clear-OutputPath {
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
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath = $Script:PsDscOutputPath
    )

    Write-Verbose ('[{0}] Removing output path {1}' -f $MyInvocation.MyCommand, $OutputPath)
    Remove-Item -Path $OutputPath -Force

    Write-Verbose ('[{0}] Making sure that the output path exists' -f $MyInvocation.MyCommand)
    Assert-OutputPath

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Assert-DscCheckSum {
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
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = $Script:PsDscOutputPath
    )

    Write-Verbose ('[{0}] Creating checksum in {1}' -f $MyInvocation.MyCommand, $Path)

    Write-Verbose ('[{0}] Making sure that the output path exists' -f $MyInvocation.MyCommand)
    Assert-OutputPath

    Write-Verbose ('[{0}] Creating checksum in {1}' -f $MyInvocation.MyCommand, $Path)
    New-DscCheckSum -ConfigurationPath $OutputPath

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}