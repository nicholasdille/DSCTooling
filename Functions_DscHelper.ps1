function New-SimpleCimSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
    )

    $params = @{}
                           $params.Add('ComputerName',    $ComputerName)
    if ($CredentialName) { $params.Add('Credential',      (Get-CredentialFromStore -CredentialName $CredentialName)) }

    $CimSession = New-CimSession @params
    if (-Not $CimSession) {
        throw ('Failed to create PowerShell remote session to <{0}>. Aborting.' -f $ComputerName)
    }

    $CimSession
}

function Get-DscMetaConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
        ,
        [Parameter(Mandatory=$true,ParameterSetName='CimSession')]
        [ValidateNotNullOrEmpty()]
        [CimSession]
        $CimSession
    )

    if (-Not $CimSession) {
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Get-DscLocalConfigurationManager -CimSession $CimSession
}

function Get-DscConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
        ,
        [Parameter(Mandatory=$true,ParameterSetName='CimSession')]
        [ValidateNotNullOrEmpty()]
        [CimSession]
        $CimSession
    )

    if (-Not $CimSession) {
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Get-DscConfiguration -CimSession $CimSession
}