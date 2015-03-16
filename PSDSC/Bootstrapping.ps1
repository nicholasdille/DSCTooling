function Get-CaRootCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RootCACertURL
    )

    $ErrorActionPreference = 'Stop'
    [String]$CertificateName = $RootCACertURL.Split('/')[-1]

    try {
        Write-Output -InputObject "Downloading Root CA Certificate from: $RootCACertURL"
        Invoke-WebRequest $RootCACertURL -OutFile .\$CertificateName -Verbose
        Write-Output -InputObject 'Succesfully downloaded Certificate'

    } catch {
        Write-Error -Message "Failed Downloading Root CA Certificate from: $RootCACertURL" -Exception $_.exception
        throw $_
    }

    try {
        Write-Output -InputObject "Importing Root CA Certificate $CertificateName in Trusted Root Computer Store"
        Import-Certificate -FilePath .\$CertificateName -CertStoreLocation Cert:\LocalMachine\Root -Verbose
        Write-Output -InputObject 'Succesfully imported certificate'

    } catch {
        Write-Error -Message "Failed Importing Root CA Certificate: $CertificateName" -Exception $_.exception
        throw $_
    }
}

function New-NodeBootstrapFromPfxSite {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ConfigurationId
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $PullServer
        ,
        [Parameter(Mandatory=$false)]
        [ValidateSet('ApplyOnly', 'ApplyAndMonitor', 'ApplyAndAutoCorrect')]
        [string]
        $ConfigurationMode = 'ApplyAndAutoCorrect'
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RebootNodeIfNeeded = 'true'
        ,
        [Parameter(Mandatory=$false)]
        [ValidateRange(15,22320)]
        [int]
        $ConfigurationModeFrequencyMins = 15
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PfxServer
    )

    $ErrorActionPreference = 'Stop'
    $PWDURI = "https://$PFXURL/$ConfigurationId.txt"
    $PFXURI = "https://$PFXURL/$ConfigurationId.pfx"
    $RebootNode = $RebootNodeIfNeeded.ToBoolean($_)

    try {
        Write-Output -InputObject "Downloading PFX password file using URI: $PWDURI"
        Invoke-WebRequest -Uri $PWDURI `
                          -OutFile .\$ConfigurationId.txt `
                          -Verbose `
                          -Certificate (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object {$_.FriendlyName -eq 'DSCPullServerAuthentication'})
        Write-Output -InputObject 'Successfully downloaded PFX password file'

    } catch {
        Write-Error -Message "Failed Downloading PFX password file using URI: $PWDURI" -Exception $_.exception
        throw $_
    }

    try {
        Write-Output -InputObject "Downloading PFX file using URI: $PFXURI"
        Invoke-WebRequest -Uri $PFXURI `
                          -OutFile .\$ConfigurationId.pfx `
                          -Verbose `
                          -Certificate (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object {$_.FriendlyName -eq 'DSCPullServerAuthentication'})
        Write-Output -InputObject 'Successfully downloaded PFX file'

    } catch {
        Write-Error -Message "Failed Downloading PFX file using URI: $PFXURI" -Exception $_.exception
        throw $_
    }

    try {
        Write-Output -InputObject 'Importing PFX'
        [SecureString]$Pin = Get-Content .\$ConfigurationId.txt | ConvertTo-SecureString -AsPlainText -Force
        $Certificate = Import-PfxCertificate -FilePath .\$ConfigurationId.pfx `
                                             -CertStoreLocation Cert:\LocalMachine\My `
                                             -Password $Pin `
                                             -Verbose
        Write-Output -InputObject 'Successfully Imported PFX file'

    } catch {
        Write-Error -Message "Failed Importing PFX file $ConfigurationId" -Exception $_.exception
        throw $_
    }

    try {
        Write-Output -InputObject 'Setting Certificate FriendlyName property'
        $Cert = Get-Item Cert:\LocalMachine\My\$($Certificate.Thumbprint)
        $Cert.FriendlyName = 'DSCEncryption'
        Write-Output -InputObject 'Successfully Set Certificate FriendlyName property'

    } catch {
        Write-Error -Message "Failed Setting Certificate FriendlyName property for: $($Certificate.Certificate.Thumbprint)" -Exception $_.exception
        throw $_
    }

    Remove-Item -Path .\$ConfigurationId.txt -Force
    Remove-Item -Path .\$ConfigurationId.pfx -Force

    Configuration LCM
    {
        Node 'localhost'
        {
            LocalConfigurationManager
            {
                ConfigurationModeFrequencyMins = $ConfigurationModeFrequencyMins
                RefreshFrequencyMins = $ConfigurationModeFrequencyMins * 2
                RebootNodeIfNeeded = $RebootNode
                ConfigurationMode =  $ConfigurationMode
                ConfigurationID = $ConfigurationId
                DownloadManagerCustomData = @{
                    ServerUrl = "https://$PullServer/PSDSCPullServer.svc";
                    AllowUnsecureConnection = 'false';
                    CertificateID = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -eq 'DSCPullServerAuthentication'}).Thumbprint;
                }
                DownloadManagerName = 'WebDownloadManager'
                RefreshMode = 'Pull'
                CertificateID = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.FriendlyName -eq 'DSCEncryption'} | Sort-Object -Property NotBefore -Descending)[0].Thumbprint;
            }
        }
    }

    try {
        Write-Output -InputObject 'Configuring LCM'
        LCM
        Set-DscLocalConfigurationManager .\LCM -Verbose
        Write-Output -InputObject 'Succesfully configured LCM'

    } catch {
        Write-Error -Message 'Failed Configuring LCM' -Exception $_.exception
        throw $_
    }

    #Update-DscConfiguration
    Remove-Item .\LCM -Recurse -Force
}