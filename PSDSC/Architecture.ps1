function New-CertificateAuthority {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CAName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CDPURL
        ,
        [Parameter(Mandatory=$true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $WebenrollURL
    )
 
    #region normalize URL to FQDN
    if ($CDPURL -like 'http://*' -or $CDPURL -like 'https://*') {
        $CDPURL = $CDPURL.Split('/')[2]
    }
 
    if ($WebenrollURL -like 'http://*' -or $WebenrollURL -like 'https://*') {
        $WebenrollURL = $WebenrollURL.Split('/')[2]
    }
    #endregion normalize URL to FQDN
 
    #region checks
    if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Verbose 'Script can only run elevated' -Verbose
        break
    }

    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
    if (!($WindowsPrincipal.IsInRole('Enterprise Admins'))) {
        Write-Verbose 'Script can only run with Enterprise Administrator privileges' -Verbose
        break
    }
    #endregion checks
 
    #region install required roles and features
    Install-WindowsFeature -Name ADCS-Cert-Authority,ADCS-Enroll-Web-Pol,ADCS-Enroll-Web-Svc -IncludeManagementTools
    #endregion install required roles and features
 
    #region Install Enterprise Root CA
    try {
        Install-AdcsCertificationAuthority -WhatIf

    } catch {
        Write-Verbose 'A CA is already installed on this server, cleanup server and AD before running this script again' -Verbose
        break
    }
    if ((certutil.exe -adca |Select-String 'cn =').line.Substring(7) -contains $CAName) {
        Write-Verbose "An Enterprise CA with the CA Name $CAName already exists" -Verbose
        break
    }
 
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
 
    #region configure CA settings and prepare AIA / CDP
    New-Item c:\CDP -ItemType directory -Force
    Copy-Item C:\Windows\System32\CertSrv\CertEnroll\*.crt C:\CDP\$CAName.crt -Force
    Get-CAAuthorityInformationAccess | Remove-CAAuthorityInformationAccess -Force
    Get-CACrlDistributionPoint | Remove-CACrlDistributionPoint -Force
    Add-CAAuthorityInformationAccess -Uri http://$CDPURL/$CAName.crt -AddToCertificateAia -Force
    Add-CACrlDistributionPoint -Uri C:\CDP\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl -PublishToServer -PublishDeltaToServer -Force
    Add-CACrlDistributionPoint -Uri http://$CDPURL/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl -AddToCertificateCdp -AddToFreshestCrl -Force
    #endregion configure CA settings and prepare AIA / CDP
 
    #region create CDP / AIA web site
    Import-Module 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\WebAdministration\WebAdministration.psd1'
    New-Website -Name CDP -HostHeader $CDPURL -Port 80 -IPAddress * -Force
    Set-ItemProperty 'IIS:\Sites\CDP' -Name physicalpath -Value C:\CDP
    Set-WebConfigurationProperty -PSPath 'IIS:\Sites\CDP' -Filter /system.webServer/directoryBrowse  -Name enabled -Value true
    Set-WebConfigurationProperty -PSPath 'IIS:\Sites\CDP' -Filter /system.webServer/security/requestfiltering  -Name allowDoubleEscaping -Value true
    attrib.exe +h C:\CDP\web.config
    #endregion create CDP / AIA web site
 
    #region restart CA service and publish CRL
    Restart-Service -Name CertSvc
    Start-Sleep -Seconds 5
    certutil.exe -CRL
    #endregion restart CA service and publish CRL

    #region add webserver template
    Invoke-Command -ComputerName ($env:LOGONSERVER).Trim('\') -ScriptBlock {
        $DN = (Get-ADDomain).DistinguishedName
        $WebTemplate = "CN=WebServer,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DN"
        dsacls.exe $WebTemplate /G 'Authenticated Users:CA;Enroll'
    }
    certutil.exe -setcatemplates +WebServer
    #endregion add webserver template
 
    #region request web server certificate
    $cert = Get-Certificate -Template webserver -DnsName $webenrollURL -SubjectName "CN=$webenrollURL" -CertStoreLocation cert:\LocalMachine\My
    #endregion request web server certificate

    #region Install enrollment web services
    Install-AdcsEnrollmentPolicyWebService -AuthenticationType UserName -SSLCertThumbprint $cert.Certificate.Thumbprint -Force
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST/Default Web Site/ADPolicyProvider_CEP_UsernamePassword'  -filter "appSettings/add[@key='FriendlyName']" -name 'value' -value 'DSC CA' -Force
    Install-AdcsEnrollmentWebService -AuthenticationType UserName -SSLCertThumbprint $cert.Certificate.Thumbprint -Force
    #endregion Install enrollment web services

    #region modify Enrollment Server URL in AD
    Invoke-Command -ComputerName ($env:LOGONSERVER).Trim('\') -ScriptBlock {
        param(
            $CAName,
            $webenrollURL
        )
        $DN = (Get-ADDomain).DistinguishedName
        $CAEnrollmentServiceDN = "CN=$CAName,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$DN"
        Set-ADObject $CAEnrollmentServiceDN -Replace @{'msPKI-Enrollment-Servers'="1`n4`n0`nhttps://$webenrollURL/$CAName`_CES_UsernamePassword/service.svc/CES`n0"}
    } -ArgumentList $CAName, $webenrollURL
    #endregion modify Enrollment Server URL in AD
}

function NewDscPullServer {
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
 
    #region checks
    if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Verbose 'Script can only run elevated' -Verbose
        break
    }
    #endregion checks
 
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

function New-PfxDownloadSite {
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
        $PFXFQDN
    )
 
    #region checks
    if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
        Write-Verbose 'Script can only run elevated' -Verbose
        break
    }
    #endregion checks
 
    #region request webserver certificate
    try {
        $PFXWebCert = Get-Certificate -Url $WebenrollURL `
                                      -Template webserver `
                                      -SubjectName "CN=$PFXFQDN" `
                                      -DnsName $PFXFQDN `
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
    Install-WindowsFeature -Name Web-Server,Web-Cert-Auth -IncludeManagementTools
    #endregion install roles and features
 
    #region prepare website directory
    $DestinationPath = (New-Item -Path C:\PFXSite -ItemType directory -Force).FullName
    #endregion prepare website directory
 
    #region import webadmin ps module
    Import-Module 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\WebAdministration\WebAdministration.psd1'
    #endregion import webadmin ps module
 
    #region configure IIS Aplication Pool
    $AppPool = New-WebAppPool -Name PFXWS -Force
    #endregion configure IIS Aplication Pool
 
    #region create site
    $WebSite = New-Website -Name PFX `
                           -PhysicalPath $DestinationPath `
                           -ApplicationPool $AppPool.name `
                           -Port 443 `
                           -IPAddress * `
                           -Ssl `
                           -SslFlags 1 `
                           -HostHeader $PFXFQDN `
                           -Force
    New-Item -Path "IIS:\SslBindings\!443!$PFXFQDN" -Value $PFXWebCert.Certificate -SSLFlags 1 | Out-Null
    #endregion create site
 
    #region unlock config data
    Set-WebConfiguration -PSPath IIS:\ -Filter //access -Metadata overrideMode -value Allow -Force
    Set-WebConfiguration -PSPath IIS:\ -Filter //iisClientCertificateMappingAuthentication -Metadata overrideMode -value Allow -Force
    #endregion unlock config data
 
    #region disabe anonymous logon
    Set-WebConfigurationProperty -PSPath $WebSite.PSPath  -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name 'enabled' -Value 'False' -Force
    #endregion disable anonymous logon
  
    #region require client auth certificates
    Set-WebConfiguration -PSPath $WebSite.PSPath -Filter 'system.webserver/security/access' -Value 'Ssl, SslNegotiateCert, SslRequireCert, Ssl128' -Force
    #endregion require client auth certificates
 
    #region create local user for Cert mapping
    # nice simple password generation one-liner by G.A.F.F Jakobs
    # https://gallery.technet.microsoft.com/scriptcenter/Simple-random-code-b2c9c9c9
    $PFXUserPWD = ([char[]](Get-Random -Input $(48..57 + 65..90 + 97..122) -Count 12)) -join ''
 
    $Computer = [ADSI]'WinNT://.,Computer'
    $PFXUser = $Computer.Create('User', 'PFXUser')
    $PFXUser.SetPassword($PFXUserPWD)
    $PFXUser.SetInfo()
    $PFXUser.Description = 'PFX User for Client Certificate Authentication binding '
    $PFXUser.SetInfo()
    $PFXUser.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
    $PFXUser.SetInfo()
    ([ADSI]'WinNT://./IIS_IUSRS,group').Add('WinNT://PFXUser,user')  
    #endregion create local user for Cert mapping
 
    #region configure certificate mapping
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings' -Name '.' -Value @{name='PFX Web Client';description='PFX Web Client';userName='PFXUser';password=$PFXUserPWD}
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings/add[@name='PFX Web Client']/rules" -Name '.' -Value @{certificateField='Issuer';certificateSubField='CN';matchCriteria=$PFXWebCert.Certificate.Issuer.Split(',')[0].trimstart('CN=');compareCaseSensitive='False'}
    Set-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisclientCertificateMappingAuthentication' -Name 'enabled' -Value 'True'
    Set-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisclientCertificateMappingAuthentication' -Name 'manyToOneCertificateMappingsEnabled' -Value 'True'
    Set-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication' -Name 'oneToOneCertificateMappingsEnabled' -Value 'False'
    #endregion configure certificate mapping
 
    #region configure deny other client certificates
    Add-WebConfigurationProperty -PSPath $WebSite.PSPath -Filter 'system.webServer/security/authentication/iisClientCertificateMappingAuthentication/manyToOneMappings' -name '.' -value @{name='Deny';description='Deny';permissionMode='Deny'}
    #endregion configure deny other client certificates
 
    #region set WebFolder ACL
    $Acl = Get-Acl -Path C:\PFXSite
    $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule('PFXUser','ReadAndExecute, Synchronize','ContainerInherit, ObjectInherit','None','Allow')
    $Acl.SetAccessRule($Ar)
    Set-Acl -Path C:\PFXSite -AclObject $Acl
    #endregion set WebFolder ACL
}