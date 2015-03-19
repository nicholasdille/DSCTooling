function Get-DscMetaConfig {
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

    Write-Verbose ('[{0}] Retrieving meta configuration' -f $MyInvocation.MyCommand)

    if (-Not $CimSession) {
        Write-Verbose ('[{0}] Connecting to computer {1}' -f $MyInvocation.MyCommand, $ComputerName)
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Write-Verbose ('[{0}] Using CIM session to computer {1}' -f $MyInvocation.MyCommand, $CimSession.ComputerName)

    Write-Verbose ('[{0}] Retrieving meta configuration' -f $MyInvocation.MyCommand)
    $MetaConfig = Get-DscLocalConfigurationManager -CimSession $CimSession

    Write-Verbose ('[{0}] Done and returning meta configuration' -f $MyInvocation.MyCommand)
    $MetaConfig
}

function Get-DscConfig {
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

    Write-Verbose ('[{0}] Retrieving node configuration' -f $MyInvocation.MyCommand)

    if (-Not $CimSession) {
        Write-Verbose ('[{0}] Connecting to computer {1}' -f $MyInvocation.MyCommand, $ComputerName)
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Write-Verbose ('[{0}] Using CIM session to computer {1}' -f $MyInvocation.MyCommand, $CimSession.ComputerName)

    Write-Verbose ('[{0}] Retrieving meta configuration' -f $MyInvocation.MyCommand)
    $NodeConfig = Get-DscConfiguration -CimSession $CimSession

    Write-Verbose ('[{0}] Done and returning node configuration' -f $MyInvocation.MyCommand)
    $NodeConfig
}

function Invoke-ConfigCheck {
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

    Write-Verbose ('[{0}] Initiating configuration check' -f $MyInvocation.MyCommand)

    $Flags = @{
        UnknownFlag1 = 1
        UnknownFlag2 = 2
        UnknownFlag3 = 3
    }

    if (-Not $CimSession) {
        Write-Verbose ('[{0}] Connecting to computer {1}' -f $MyInvocation.MyCommand, $ComputerName)
        $PSBoundParameters.Remove('Type')
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Write-Verbose ('[{0}] Using CIM session to computer {1}' -f $MyInvocation.MyCommand, $CimSession.ComputerName)

    Write-Verbose ('[{0}] Invoking CIM method' -f $MyInvocation.MyCommand)
    $params = @{
        Namespace  = 'root/Microsoft/Windows/DesiredStateConfiguration'
        ClassName  = 'MSFT_DSCLocalConfigurationManager'
        MethodName = 'PerformRequiredConfigurationChecks'
        Arguments  = @{Flags = [System.UInt32]$Flags.$Type}
        CimSession = $CimSession
    }
    Invoke-CimMethod @params

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Invoke-ConsistencyTask {
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

    Write-Verbose ('[{0}] Initiating configuration check' -f $MyInvocation.MyCommand)

    if (-Not $CimSession) {
        Write-Verbose ('[{0}] Connecting to computer {1}' -f $MyInvocation.MyCommand, $ComputerName)
        $CimSession = New-SimpleCimSession @PSBoundParameters
    }
    Write-Verbose ('[{0}] Using CIM session to computer {1}' -f $MyInvocation.MyCommand, $CimSession.ComputerName)

    Write-Verbose ('[{0}] Initiating configuration check' -f $MyInvocation.MyCommand)
    Get-ScheduledTask -CimSession $CimSession -TaskName Consistency | Start-ScheduledTask

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}