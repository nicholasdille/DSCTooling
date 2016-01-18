function Enable-WindowsRemoteManagement {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainName
    )

    Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts "*.$DomainName" -Force
}

function Enable-CredSSP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainName
    )

    Enable-WSManCredSSP -Role Server -Force
    Enable-WSManCredSSP -Role Client -DelegateComputer "*.$DomainName" -Force
}

function Set-IpConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [int]
        $InterfaceIndex
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $IPAddress
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [int]
        $PrefixLength
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Gateway
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $DnsServer
    )

    New-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress $IpAddress -PrefixLength $PrefixLength
    Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $DnsServer
}

function Install-DomainController {
    #Requires -Version 3
    #Requires -RunAsAdministrator
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainName
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainNetBiosName
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [SecureString]
        $SafeModeAdminPassword
    )

    #region Setting variables
    if (-not $DomainNetBiosName) {
        $DomainNetbiosName = $DomainName.split('.')[0]
    }
    #endregion Setting variables

    Try {
        #region Install Windows features
        Install-WindowsFeature -Name AD-Domain-Services,DNS -ErrorAction Stop
        Install-WindowsFeature -Name RSAT-ADDS-Tools -ErrorAction SilentlyContinue
        #endregion Install Windows features
        
        #region Set password not to expire
        $account = [ADSI]("WinNT://$env:COMPUTERNAME/Administrator,user")
        $account.invokeSet('userFlags', ($account.userFlags[0] -BOR 65536))
        $account.commitChanges() 
        #endregion Set password not to expire
    
        #region Create domain
        #Import-Module ADDSDeployment        
        $Arguments = @{
            CreateDnsDelegation = $false 
            DatabasePath = 'C:\Windows\NTDS' 
            DomainMode = 'Win2012R2' 
            DomainName = $DomainName
            DomainNetbiosName = $DomainNetbiosName
            ForestMode = 'Win2012R2'
            InstallDns = $true
            LogPath = 'C:\Windows\NTDS'
            NoRebootOnCompletion = $true
            SysvolPath = 'C:\Windows\SYSVOL'
            SafeModeAdministratorPassword = $SafeModeAdminPassword
            Force = $True
        }
        Install-ADDSForest @Arguments
        #endregion Create domain

    } Catch {
        Throw $_
    }
}

function Install-Dns {
    #Requires -Version 3
    #Requires -RunAsAdministrator
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Zone
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $NetworkId
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ScavengeServer
    )

    Try {
        #region Install Windows feature
        Install-WindowsFeature -Name RSAT-DNS-Server
        #endregion Install Windows feature

        #region Configure forward zone
        Set-DnsServerPrimaryZone –Name $Zone –ReplicationScope Forest
        Set-DnsServerScavenging –ScavengingState $True –RefreshInterval 7:00:00:00 –NoRefreshInterval 7:00:00:00 –ScavengingInterval 7:00:00:00 –ApplyOnAllZones
        if (-not $ScavengeServer) {
            $ScavengeServer = Get-NetAdapter | Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
        }
        Set-DnsServerZoneAging -Name $Zone –Aging $True –NoRefreshInterval 7:00:00:00 –RefreshInterval 7:00:00:00 –ScavengeServers $ScavengeServer
        #endregion Configure forward zone

        #region Configure reverse zone
        $ReverseZone = Add-DnsServerPrimaryZone –ReplicationScope 'Forest' –NetworkId $NetworkID –DynamicUpdate Secure –PassThru
        Set-DnsServerZoneAging -Name $ReverseZone.ZoneName –Aging $True –NoRefreshInterval 7:00:00:00 –RefreshInterval 7:00:00:00
        #endregion Configure reverse zone

    } Catch {
        Throw $_
    }
}

function Install-Dhcp {
    #Requires -Version 3
    #Requires -RunAsAdministrator
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $DNSDomain = $env:USERDNSDOMAIN
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $DNSServerIP
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $StartRange
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $EndRange
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Netmask = '255.255.255.0'
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Gateway
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $LeaseDuration = '1.00:00:00'
    )

    Try {
        #region Install Windows feature
        Install-WindowsFeature -Name DHCP
        #endregion Install Windows feature

        #region Create security groups for delegation
        Start-Process -FilePath cmd.exe -ArgumentList "/c 'netsh dhcp add securitygroups'" -Wait    
        Restart-service dhcpserver
        #endregion Create security groups for delegation

        #region Authorize DHCP server in Active Directory
        Add-DhcpServerInDC -DnsName $Env:COMPUTERNAME
        #endregion Authorize DHCP server in Active Directory

        #region Notify the Server Manager that the post-install configuration has been completed successfully
        Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2
        #region Notify the Server Manager that the post-install configuration has been completed successfully

        #region Add and configure scope
        $ServerIp = Get-NetAdapter | Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
        if (-not $DNSServerIP) {
            $DNSServerIP = $ServerIp
        }
        Add-DhcpServerV4Scope -Name $DNSDomain -StartRange $StartRange -EndRange $EndRange -SubnetMask $Netmask
        Set-DhcpServerV4OptionValue -DnsDomain $DNSDomain -DnsServer $DNSServerIP -Router $Gateway                   
        Set-DhcpServerv4Scope -ScopeId $ServerIp -LeaseDuration $LeaseDuration
        #endregion Add and configure scope

    } Catch {
        Throw $_
    }
}

function Install-CertificateAuthority {
    #Requires -Version 3
    #Requires -RunAsAdministrator
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CAName
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $CDPURL = "cdp.$env:USERDNSDOMAIN"
        ,
        [Parameter()]
        [string]
        [ValidateNotNullOrEmpty()]
        $WebenrollURL = "webenroll.$env:USERDNSDOMAIN"
    )
 
    #region normalize URL to FQDN
    if ($CDPURL -like 'http://*' -or $CDPURL -like 'https://*') {
        $CDPURL = $CDPURL.Split('/')[2]
    }
 
    if ($WebenrollURL -like 'http://*' -or $WebenrollURL -like 'https://*') {
        $WebenrollURL = $WebenrollURL.Split('/')[2]
    }
    #endregion normalize URL to FQDN

    #region Prepare DNS resolution
    $ServerIp = Get-NetAdapter | Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
    if (Resolve-DnsName -Name $CDPURL -ErrorAction SilentlyContinue) {
        Add-DnsServerPrimaryZone -Name $CDPURL -ReplicationScope Forest
        Add-DnsServerResourceRecordA -ZoneName $CDPURL -Name $CDPURL -IPv4Address $ServerIp
    }
    if (Resolve-DnsName -Name $WebenrollURL -ErrorAction SilentlyContinue) {
        Add-DnsServerPrimaryZone -Name $WebenrollURL -ReplicationScope Forest
        Add-DnsServerResourceRecordA -ZoneName $WebenrollURL -Name $WebenrollURL -IPv4Address $ServerIp
    }
    #endregion Prepare DNS resolution
 
    #region install required roles and features
    Install-WindowsFeature -Name ADCS-Cert-Authority,ADCS-Enroll-Web-Pol,ADCS-Enroll-Web-Svc -IncludeManagementTools
    #endregion install required roles and features
 
    #region Install Enterprise Root CA
    New-Item C:\Windows\capolicy.inf -ItemType file -Force | Out-Null
    @"
[Version]
Signature="`$Windows NT$"
[PolicyStatementExtension]
Policies=InternalUseOnly
[InternalUseOnly]
OID=2.5.29.32.0
Notice="This CA is used for a DSC demo environment"
[Certsrv_Server]
LoadDefaultTemplates=0
AlternateSignatureAlgorithm=1
[Extensions]
2.5.29.15 = AwIBBg==
Critical = 2.5.29.15
"@ | Out-File C:\Windows\capolicy.inf -Force
    Install-AdcsCertificationAuthority -CACommonName $CAName `
                                       -CAType EnterpriseRootCA `
                                       -CADistinguishedNameSuffix 'O=DSCCompany,C=NL' `
                                       -HashAlgorithmName sha256 `
                                       -ValidityPeriod Years `
                                       -ValidityPeriodUnits 10 `
                                       -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' `
                                       -KeyLength 4096 `
                                       -Force
 
    certutil.exe -setreg CA\AuditFilter 127
    certutil.exe -setreg CA\ValidityPeriodUnits 4
    certutil.exe -setreg CA\ValidityPeriod 'Years'
    #endregion Install Enterprise Root CA
 
    #region Configure CA settings and prepare AIA / CDP
    New-Item c:\CDP -ItemType directory -Force
    Copy-Item C:\Windows\System32\CertSrv\CertEnroll\*.crt C:\CDP\$CAName.crt -Force
    Get-CAAuthorityInformationAccess | Remove-CAAuthorityInformationAccess -Force
    Get-CACrlDistributionPoint | Remove-CACrlDistributionPoint -Force
    Add-CAAuthorityInformationAccess -Uri http://$CDPURL/$CAName.crt -AddToCertificateAia -Force
    Add-CACrlDistributionPoint -Uri C:\CDP\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACrlDistributionPoint -Uri http://$CDPURL/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl -AddToCertificateCdp -AddToFreshestCrl -Force
    #endregion Configure CA settings and prepare AIA / CDP
 
    #region Create CDP / AIA web site
    Import-Module 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\WebAdministration\WebAdministration.psd1'
    New-Website -Name CDP -HostHeader $CDPURL -Port 80 -IPAddress * -Force
    Set-ItemProperty 'IIS:\Sites\CDP' -Name physicalpath -Value C:\CDP
    Set-WebConfigurationProperty -PSPath 'IIS:\Sites\CDP' -Filter /system.webServer/directoryBrowse  -Name enabled -Value true
    Set-WebConfigurationProperty -PSPath 'IIS:\Sites\CDP' -Filter /system.webServer/security/requestfiltering  -Name allowDoubleEscaping -Value true
    attrib.exe +h C:\CDP\web.config
    #endregion Create CDP / AIA web site
 
    #region Restart CA service and publish CRL
    Restart-Service -Name CertSvc
    Start-Sleep -Seconds 5
    certutil.exe -CRL
    #endregion Restart CA service and publish CRL

    #region Add webserver template
    Invoke-Command -ComputerName ($env:LOGONSERVER).Trim('\') -ScriptBlock {
        $DN = (Get-ADDomain).DistinguishedName
        $WebTemplate = "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DN"
        dsacls.exe $WebTemplate /G 'Authenticated Users:CA;Enroll'
    }
    certutil.exe -setcatemplates +WebServer
    #endregion Add webserver template
 
    #region Request web server certificate
    $cert = Get-Certificate -Template webserver -DnsName $webenrollURL -SubjectName "CN=$webenrollURL" -CertStoreLocation cert:\LocalMachine\My
    #endregion Request web server certificate

    #region Install enrollment web services
    Install-AdcsEnrollmentPolicyWebService -AuthenticationType UserName -SSLCertThumbprint $cert.Certificate.Thumbprint -Force
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site/ADPolicyProvider_CEP_UsernamePassword'  -filter "appSettings/add[@key='FriendlyName']" -name 'value' -value 'DSC CA' -Force
    Install-AdcsEnrollmentWebService -AuthenticationType UserName -SSLCertThumbprint $cert.Certificate.Thumbprint -Force
    #endregion Install enrollment web services

    #region Modify Enrollment Server URL in AD
    Invoke-Command -ComputerName ($env:LOGONSERVER).Trim('\') -ScriptBlock {
        param(
            $CAName,
            $webenrollURL
        )
        $DN = (Get-ADDomain).DistinguishedName
        $CAEnrollmentServiceDN = "CN=$CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DN"
        Set-ADObject $CAEnrollmentServiceDN -Replace @{'msPKI-Enrollment-Servers'="1`n4`n0`nhttps://$webenrollURL/$CAName`_CES_UsernamePassword/service.svc/CES`n0"}
    } -ArgumentList $CAName, $webenrollURL
    #endregion Modify Enrollment Server URL in AD
}

function Install-AdminTools {
    Install-WindowsFeature -Name RSAT-ADDS-Tools,RSAT-AD-AdminCenter
    Install-WindowsFeature -Name RSAT-DNS
    Install-WindowsFeature -Name RSAT-DHCP
    Install-WindowsFeature -Name RSAT-ADCS -IncludeAllSubFeature
}

function Install-FileServer {
    [CmdletBinding()]
    param()

    try {
        #region Install Windows features
        Install-WindowsFeature -Name FS-FileServer,FS-iSCSITarget-Server,iSCSITarget-VSS-VDS -IncludeManagementTools
        Install-WindowsFeature -Name RSAT-CoreFile-Mgmt
        #endregion Install Windows features

        #region Create file shares
        New-Item -ItemType Directory -Path c:\Storage1 -Force
        New-SmbShare -Name Storage1 -Path c:\Storage1 -FullAccess EVERYONE
        New-Item -ItemType Directory -Path c:\Storage2 -Force
        New-SmbShare -Name Storage2 -Path c:\Storage2 -FullAccess EVERYONE
        #endregion Create file shares
    
    } catch {
        throw $_
    }
}

function New-PsDscPullServer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        $CertificateCredentials
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $WebenrollURL
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DSCPullFQDN
    )
 
    #region request webserver certificate
    try {
        $DSCPullCert = Get-Certificate -Url $WebenrollURL `
                                       -Template webserver `
                                       -SubjectName "CN=$DSCPullFQDN" `
                                       -DnsName $DSCPullFQDN `
                                       -CertStoreLocation Cert:\LocalMachine\My `
                                       -Credential $CertificateCredentials `
                                       -ErrorAction Stop `
                                       -Verbose

    } catch {
        Write-Verbose 'Certificate Request did not complete successfully' -Verbose
        break
    }
    #endregion request webserver certificate
 
    #region install roles and features
    Install-WindowsFeature -Name Dsc-Service,Web-Cert-Auth -IncludeManagementTools
    #endregion install roles and features
 
    #region prepare website directory
    $DestinationPath = (New-Item -Path C:\inetpub\wwwroot\PSDSCPullServer -ItemType directory -Force).FullName
    $BinPath = (New-Item -Path $DestinationPath -Name 'bin' -ItemType directory -Force).FullName
    $SourcePath = "$pshome/modules/psdesiredstateconfiguration/pullserver"
    Copy-Item -Path $SourcePath\Global.asax -Destination $DestinationPath\Global.asax -Force | Out-Null
    Copy-Item -Path $SourcePath\PSDSCPullServer.mof -Destination $DestinationPath\PSDSCPullServer.mof -Force | Out-Null
    Copy-Item -Path $SourcePath\PSDSCPullServer.svc -Destination $DestinationPath\PSDSCPullServer.svc -Force | Out-Null
    Copy-Item -Path $SourcePath\PSDSCPullServer.xml -Destination $DestinationPath\PSDSCPullServer.xml -Force | Out-Null
    Copy-Item -Path $SourcePath\PSDSCPullServer.config -Destination $DestinationPath\web.config -Force | Out-Null
    Copy-Item -Path $SourcePath\Microsoft.Powershell.DesiredStateConfiguration.Service.dll -Destination $BinPath -Force | Out-Null
    #endregion prepare website directory
 
    #region import webadmin ps module
    Import-Module 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\WebAdministration\WebAdministration.psd1'
    #endregion import webadmin ps module
 
    #region configure IIS Aplication Pool
    $AppPool = New-WebAppPool -Name PSWS -Force
    $AppPool.processModel.identityType = 0 #configure app pool to run as local system
    $AppPool.enable32BitAppOnWin64 = $true
    $AppPool | Set-Item
    #endregion configure IIS Aplication Pool
 
    #region create site
    $WebSite = New-Website -Name PSDSCPullServer `
                           -PhysicalPath $DestinationPath `
                           -ApplicationPool $AppPool.name `
                           -Port 443 `
                           -IPAddress * `
                           -Ssl `
                           -SslFlags 1 `
                           -HostHeader $DSCPullFQDN `
                           -Force
    New-Item -Path "IIS:\SslBindings\!443!$DSCPullFQDN" -Value $DSCPullCert.Certificate -SSLFlags 1 | Out-Null
    #endregion create site
 
    #region unlock config data
    Set-WebConfiguration -PSPath IIS:\ -Filter //access -Metadata overrideMode -value Allow -Force
    Set-WebConfiguration -PSPath IIS:\ -Filter //anonymousAuthentication -Metadata overrideMode -value Allow -Force
    Set-WebConfiguration -PSPath IIS:\ -Filter //basicAuthentication -Metadata overrideMode -value Allow -Force
    Set-WebConfiguration -PSPath IIS:\ -Filter //windowsAuthentication -Metadata overrideMode -value Allow -Force
    Set-WebConfiguration -PSPath IIS:\ -Filter //iisClientCertificateMappingAuthentication -Metadata overrideMode -value Allow -Force
    #endregion unlock config data
 
    #region setup application settings
    Copy-Item -Path $pshome\Modules\PSDesiredStateConfiguration\PullServer\Devices.mdb -Destination $env:programfiles\WindowsPowerShell\DscService -Force
    $configpath = "$env:programfiles\WindowsPowerShell\DscService\Configuration"
    $modulepath = "$env:programfiles\WindowsPowerShell\DscService\Modules"
    $jet4provider = 'System.Data.OleDb'
    $jet4database = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$env:PROGRAMFILES\WindowsPowerShell\DscService\Devices.mdb;"
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath `
                                 -Filter 'appSettings' `
                                 -Name '.' `
                                 -Value @{key='dbprovider';value=$jet4provider} `
                                 -Force
 
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath `
                                 -Filter 'appSettings' `
                                 -Name '.' `
                                 -Value @{key='dbconnectionstr';value=$jet4database} `
                                 -Force
 
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath `
                                 -Filter 'appSettings' `
                                 -Name '.' `
                                 -Value @{key='ConfigurationPath';value= $configpath} `
                                 -Force
                              
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath `
                                 -Filter 'appSettings' `
                                 -Name '.' `
                                 -Value @{key='ModulePath';value= $modulepath} `
                                 -Force
    #endregion setup application settings
 
    #region require client auth certificates
    Set-WebConfiguration -PSPath $WebSite.PSPath -Filter 'system.webserver/security/access' -Value 'Ssl, SslNegotiateCert, SslRequireCert, Ssl128' -Force
    #endregion require client auth certificates
 
    #region create local user for Cert mapping
    # nice simple password generation one-liner by G.A.F.F Jakobs
    # https://gallery.technet.microsoft.com/scriptcenter/Simple-random-code-b2c9c9c9
    $DSCUserPWD = ([char[]](Get-Random -Input $(48..57 + 65..90 + 97..122) -Count 12)) -join ''
 
    $Computer = [ADSI]'WinNT://.,Computer'
    $DSCUser = $Computer.Create('User', 'DSCUser')
    $DSCUser.SetPassword($DSCUserPWD)
    $DSCUser.SetInfo()
    $DSCUser.Description = 'DSC User for Client Certificate Authentication binding '
    $DSCUser.SetInfo()
    $DSCUser.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
    $DSCUser.SetInfo()
    ([ADSI]'WinNT://./IIS_IUSRS,group').Add('WinNT://DSCUser,user')  
    #endregion create local user for Cert mapping
 
    #region configure certificate mapping
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings' -Name '.' -Value @{name='DSC Pull Client';description='DSC Pull Client';userName='DSCUser';password=$DSCUserPWD}
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings/add[@name='DSC Pull Client']/rules" -Name '.' -Value @{certificateField='Issuer';certificateSubField='CN';matchCriteria=$DSCPullCert.Certificate.Issuer.Split(',')[0].trimstart('CN=');compareCaseSensitive='False'}
    Set-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisclientCertificateMappingAuthentication' -Name 'enabled' -Value 'True'
    Set-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisclientCertificateMappingAuthentication' -Name 'manyToOneCertificateMappingsEnabled' -Value 'True'
    Set-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication' -Name 'oneToOneCertificateMappingsEnabled' -Value 'False'
    #endregion configure certificate mapping
 
    #region configure deny other client certificates
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings' -name '.' -value @{name='Deny';description='Deny';permissionMode='Deny'}
    #endregion configure deny other client certificates
 
    #region enable CAPI2 Operational Log
    $logName = 'Microsoft-Windows-CAPI2/Operational'
    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
    $log.IsEnabled=$true
    $log.SaveChanges()
    #endregion enable CAPI2 Operational Log
 
    #region remove default web site
    #Stop-Website -Name 'Default Web Site'
    #Remove-Website -Name 'Default Web Site'
    #endregion remove default web site
}

workflow Rename-Computer2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewName
    )

    Rename-Computer -NewName $NewName -Restart
}

function Deploy-DomainControllerPhase1 {
#workflow Deploy-DomainControllerPhase1 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $IPAddress
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Netmask
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [int]
        $PrefixLength
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Gateway
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DnsServer
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainName
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainNetBiosName
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [SecureString]
        $SafeModeAdminPassword
    )

    #region Process
    Enable-WindowsRemoteManagement -DomainName $DomainName
    Enable-CredSSP -DomainName $DomainName

    Set-WinUserLanguageList -LanguageList de-de -Force
    $InterfaceIndex = Get-NetAdapter | Select-Object -ExpandProperty ifIndex
    Set-IpConfiguration -InterfaceIndex $InterfaceIndex -IPAddress $IPAddress -PrefixLength $PrefixLength -Gateway $Gateway -DnsServer $DnsServer
    Install-DomainController -DomainName $DomainName -DomainNetBiosName $DomainNetBiosName -SafeModeAdminPassword $SafeModeAdminPassword
    Restart-Computer
    #endregion Process
}

function Deploy-DomainControllerPhase2 {
#workflow Deploy-DomainControllerPhase2 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainName
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $IPAddress
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Netmask
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Gateway
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RangeStart
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RangeEnd
        ,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CAName
    )

    #region Process
    Install-Dns -Zone $DomainName -NetworkId $IPAddress
    Install-Dhcp -DNSDomain $DomainName -DNSServerIP $IPAddress -StartRange $RangeStart -EndRange $RangeEnd -Netmask $Netmask -Gateway $Gateway
    Install-CertificateAuthority -CAName $CAName
    #endregion Process
}

$IPAddress = '10.0.0.2'
$Netmask = '255.255.255.0'
$PrefixLength = 24
$Gateway = '10.0.0.1'
$DnsServer = '127.0.0.1'
$DomainName = 'inmylab.de'
$DomainNetBiosName = 'LAB'
$SafeModeAdminPassword = Read-Host -Prompt 'Enter safe mode admin password' -AsSecureString
$CAName = 'CA-inmylab'
$RangeStart = '10.0.0.100'
$RangeEnd = '10.0.0.199'

#Deploy-DomainControllerPhase1 <#-PSComputerName 10.0.0.100 -PSCredential (Get-Credential)#> -IPAddress $IPAddress -Netmask $Netmask -PrefixLength $PrefixLength -Gateway $Gateway -DnsServer $DnsServer -DomainName $DomainName -DomainNetBiosName $DomainNetBiosName -SafeModeAdminPassword $SafeModeAdminPassword
#Deploy-DomainControllerPhase2 -PSComputerName 10.0.0.100 -PSCredential (Get-Credential) -DomainName $DomainName -IPAddress $IPAddress -Netmask $Netmask -Gateway $Gateway -RangeStart $RangeStart -RangeEnd $RangeEnd -CAName $CAName