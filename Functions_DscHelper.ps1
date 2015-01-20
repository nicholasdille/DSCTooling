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
        [Microsoft.Management.Infrastructure.CimSession]
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
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession
    )

    if (-Not $CimSession) {
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Get-DscConfiguration -CimSession $CimSession
}

function Invoke-ConfigCheck {
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
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession
        ,
        [Parameter(Mandatory=$false)]
        [ValidateSet('UnknownFlag1','UnknownFlag2','UnknownFlag3')]
        $Type
    )

    $Flags = @{
        UnknownFlag1 = 1
        UnknownFlag2 = 2
        UnknownFlag3 = 3
    }

    $params = @{
        Namespace  = 'root/Microsoft/Windows/DesiredStateConfiguration'
        ClassName  = 'MSFT_DSCLocalConfigurationManager'
        MethodName = 'PerformRequiredConfigurationChecks'
        Arguments  = @{Flags = [System.UInt32]$Flags.$Type}
    }

    if (-Not $CimSession) {
        $PSBoundParameters.Remove('Type')
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    $params.Add('CimSession', $CimSession)

    Invoke-CimMethod @params
}

function Invoke-ConsistencyTask {
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
        [Microsoft.Management.Infrastructure.CimSession]
        $CimSession
    )

    if (-Not $CimSession) {
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Get-ScheduledTask -CimSession $CimSession -TaskName Consistency | Start-ScheduledTask
}