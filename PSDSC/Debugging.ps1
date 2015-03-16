function New-WebEnrolledCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Credential
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $WebenrollServer
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Template
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FriendlyName
    )

    $WebenrollURL = "https://$WebenrollServer/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP"
    $SecPassword = ConvertTo-SecureString $Credential.Split(':')[-1] -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($Credential.Split(':')[0], $SecPassword)
    $PSBoundParameters.Credential = $Credential.Split(':')[0] + ':*******'

    try {
        Write-Output -InputObject 'Requesting Certificate using parameters:'
        Write-Output -InputObject $PSBoundParameters
        $Certificate = Get-Certificate -Url $WebenrollURL -Template $Template -SubjectName "CN=$env:COMPUTERNAME" -Credential $Cred -CertStoreLocation Cert:\LocalMachine\My -Verbose
        Write-Output -InputObject "Successfully Requested Certificate: $($Certificate.Certificate.Thumbprint)"

    } catch {
        Write-Error -Message "Failed Requesting Certificate from: $WebenrollURL" -Exception $_.exception
        throw $_
    }

    try {
        Write-Output -InputObject 'Setting Certificate FriendlyName property'
        $Cert = Get-Item Cert:\LocalMachine\My\$($Certificate.Certificate.Thumbprint)
        $Cert.FriendlyName = $FriendlyName
        Write-Output -InputObject 'Successfully Set Certificate FriendlyName property'

    } catch {
        Write-Error -Message "Failed Setting Certificate FriendlyName property for: $($Certificate.Certificate.Thumbprint)" -Exception $_.exception
        throw $_
    }
}

function Download-DscConfigurationFromPullServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PullServer
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Guid
    )

    try {
        Invoke-WebRequest `
            -Uri "https://$PullServer/PSDSCPullServer.svc/Action(ConfigurationId='$Guid')/ConfigurationContent" `
            -OutFile "c:\Windows\TEMP\$Guid.mof" `
            -Verbose `
            -Certificate (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object {$_.FriendlyName -eq 'DSCPullServerAuthentication'})

    } catch {
        #
    }
}

function Download-DscResourceFromPullServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PullServer
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Guid
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ModuleName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ModuleVersion
    )

    try {
        Invoke-WebRequest `
            -Uri "https://$PullServer/PSDSCPullServer.svc/Module(ConfigurationId='$Guid',ModuleName='$ModuleName',ModuleVersion='$ModuleVersion')/ModuleContent" `
            -OutFile "c:\Windows\TEMP\$($ModuleName)_$ModuleVersion.zip" `
            -Verbose `
            -Certificate (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object {$_.FriendlyName -eq 'DSCPullServerAuthentication'})

    } catch {
        #
    }
}