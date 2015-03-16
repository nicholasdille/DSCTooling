function Assert-Path {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path
    )

    if (-Not (Test-Path -Path $Path)) {
        New-Item -ItemType Directory -Path $Path
    }
}

function Assert-OutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath = $Script:PsDscOutputPath
    )

    Assert-Path -Path $OutputPath
}

function Clear-OutputPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath = $Script:PsDscOutputPath
    )

    Remove-Item -Path $OutputPath -Force
}

function Assert-DscCheckSum {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $OutputPath = $Script:PsDscOutputPath
    )

    Assert-OutputPath
    New-DscCheckSum -ConfigurationPath $OutputPath
}