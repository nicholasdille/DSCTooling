Configuration MasterConfiguration {
    param()

    #region Import resources
    Import-DSCResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xComputerManagement
    Import-DscResource -ModuleName xHyper-V
    Import-DscResource -ModuleName cHyper-V
    Import-DscResource -ModuleName cWindowsOS
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xRemoteDesktopAdmin
    Import-DscResource -ModuleName xSqlServer
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xPowerShellExecutionPolicy
    Import-DscResource -ModuleName xSystemSecurity
    #endregion
 
    Node $AllNodes.NodeName {

        #region Computer
        if ($Node.Roles.Keys -icontains 'Computer') {
            $NodeComputer = $Node.Roles.Computer

            if ($NodeComputer.containsKey('DomainName') -And -Not $NodeComputer.containsKey('Credentials')) {
                Write-Error 'Error in ConfigData: You specified DomainName without Credentials'
            }
            
            if ($NodeComputer.containsKey('DomainName') -And $NodeComputer.containsKey('Credentials')) {
                $DependsOn = $Null
                if ($NodeComputer.containsKey('DnsServer') -And $NodeComputer.containsKey('Adapter')) {
                    xDNSServerAddress DNS {
                        Address        = ($NodeComputer.DnsServer)
                        InterfaceAlias = $NodeComputer.Adapter
                        AddressFamily  = 'IPv4'
                    }
                    $DependsOn = ('[xDNSServerAddress]DNS')
                }

                if ($NodeComputer.containsKey('MachineName')) {
                    xComputer ComputerNameAndDomainJoin {
                        Name       = $NodeComputer.MachineName
                        DomainName = $NodeComputer.DomainName
                        Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credentials])
                        DependsOn  = $DependsOn
                    }

                } else {
                    xComputer ComputerNameAndDomainJoin {
                        DomainName = $NodeComputer.DomainName
                        Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credentials])
                        DependsOn  = $DependsOn
                    }
                }

            } else {
                xComputer ComputerNameAndDomainJoin {
                    Name       = $NodeComputer.MachineName
                }
            }
        }
        #endregion

        #region Base config
        foreach ($SslVersion in ('SSL 3.0', 'SSL 2.0')) {
            Registry ('Disable' + $SslVersion.Replace('.', '').Replace(' ','')) {
                Key = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$SslVersion\Server"
                ValueName = 'Enabled'
                ValueType = 'Dword'
                ValueData = '0'
                Ensure = 'Present'
            }
        }

        xIEEsc DisableIEEscUsers {
            IsEnabled = $false
            UserRole = 'Users'
        }
        
        xIEEsc DisableIEEscAdmins {
            IsEnabled = $false
            UserRole = 'Administrators'
        }

        xRemoteDesktopAdmin RemoteDesktopSettings {
            Ensure = 'Present'
            UserAuthentication = 'Secure'
        }

        xFirewall AllowRDP {
            Name = 'DSC - Remote Desktop Admin Connections'
            DisplayGroup = 'Remote Desktop'
            Ensure = 'Present'
            State = 'Enabled'
            Access = 'Allow'
            Profile = ('Any')
        }

        xPowerShellExecutionPolicy ExecutionPolicy {
            ExecutionPolicy = 'RemoteSigned'
        }
        #endregion
        
        #region WindowsFeature
        foreach ($WindowsFeature in $Node.WindowsFeatures) {
            WindowsFeature $WindowsFeature.Name {
                Ensure    = $WindowsFeature.Ensure
                Name      = $WindowsFeature.Name
                DependsOn = $WindowsFeature.DependsOn
            }
        }
        #endregion

        #region Service
        foreach ($Service in $Node.Services) {
            Service $Service.Name {
                Name        = $Service.Name
                StartupType = $Service.StartupType
                State       = $Service.State
                DependsOn   = $Service.DependsOn
            }
        }
        #endregion
                
        #region Registry
        foreach ($RegistrySetting in $Node.RegistrySettings) {
            Registry $RegistrySetting.ValueName {
                Ensure    = $RegistrySetting.Ensure
                Key       = $RegistrySetting.Key
                ValueName = $RegistrySetting.ValueName
                ValueType = $RegistrySetting.ValueType
                ValueData = $RegistrySetting.ValueData
                DependsOn = $RegistrySetting.DependsOn
            }
        }
        #endregion

        #region Role PullServer
        if ($Node.Roles.Keys -icontains 'PullServer') {
            $PullConfig = $Node.Roles.PullServer

            WindowsFeature DSC-Service {
                Ensure = 'Present'
                Name   = 'DSC-Service'
            }
            WindowsFeature Web-Mgmt-Service {
                Ensure = 'Present'
                Name   = 'Web-Mgmt-Service'
            }

            Service WMSVC {
                Name        = 'WMSVC'
                StartupType = 'Automatic'
                State       = 'Running'
                DependsOn   = '[WindowsFeature]Web-Mgmt-Service'
            }

            Registry EnableRemoteManagement {
                Ensure    = 'Present'
                Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server'
                ValueName = 'EnableRemoteManagement'
                ValueType = 'Dword'
                ValueData = '1'
                DependsOn = ('[WindowsFeature]Web-Mgmt-Service', '[Service]WMSVC')
            }

            $CertificateThumbPrint = 'AllowUnencryptedTraffic'
            if ($PullConfig.containsKey('CertificateThumbPrint')) {
                $CertificateThumbPrint = $PullConfig.CertificateThumbprint
            }

            xDscWebService PSDSCPullServer {
			    Ensure                  = 'Present'
			    EndpointName            = 'PSDSCPullServer'
			    Port                    = $PullConfig.PullPort
			    PhysicalPath            = "$Env:SystemDrive\inetpub\wwwroot\PSDSCPullServer"
			    CertificateThumbPrint   = $CertificateThumbPrint
			    ModulePath              = "$Env:ProgramFiles\WindowsPowerShell\DscService\Modules"
			    ConfigurationPath       = "$Env:ProgramFiles\WindowsPowerShell\DscService\Configuration"
			    State                   = 'Started'
			    DependsOn               = ('[WindowsFeature]DSC-Service')
		    }

		    xDscWebService PSDSCComplianceServer {
			    Ensure                  = 'Present'
			    EndpointName            = 'PSDSCComplianceServer'
			    Port                    = $PullConfig.CompliancePort
			    PhysicalPath            = "$Env:SystemDrive\inetpub\wwwroot\PSDSCComplianceServer"
			    CertificateThumbPrint   = $CertificateThumbPrint
			    State                   = 'Started'
			    IsComplianceServer      = $True
			    DependsOn               = ('[WindowsFeature]DSC-Service', '[xDSCWebService]PSDSCPullServer')
		    }
        }
        #endregion

        #region Role Hypervisor
        if ($Node.Roles.Keys -icontains 'Hypervisor') {
            $RoleHypervisor = $Node.Roles.Hypervisor

            #region WindowsFeature
            WindowsFeature Hyper-V {
                Ensure    = 'Present'
                Name      = 'Hyper-V'
            }
            WindowsFeature Hyper-V-PowerShell {
                Ensure    = 'Present'
                Name      = 'Hyper-V-PowerShell'
            }
            #endregion
                    
            #region Teaming
            foreach ($Team in $RoleHypervisor.Teams) {
                cNetworkTeam "Team$($Team.Name)" {
                    Name                   = $Team.Name
                    TeamingMode            = $Team.TeamingMode
                    LoadBalancingAlgorithm = $Team.LoadBalancingAlgorithm
                    TeamMembers            = $Team.Adapters
                    Ensure                 = 'Present'
                }
            }
            #endregion
 
            #region Virtual Switch
            foreach ($Switch in $RoleHypervisor.VirtualSwitches) {
                if ($Switch.Type -ieq 'External') {
                    cVMSwitch "Switch$($Switch.Name)" {
                        Name                   = $Switch.Name
                        Type                   = $Switch.Type
                        AllowManagementOS      = $false
                        MinimumBandwidthMode   = 'Weight'
                        NetAdapterName         = $Switch.Adapter
                        Ensure                 = 'Present'
                        DependsOn              = ("[cNetworkTeam]Team$($Switch.Adapter)", '[WindowsFeature]Hyper-V', '[WindowsFeature]Hyper-V-PowerShell')
                    }

                } elseif ($Switch.Type -ieq 'Private') {
                    cVMSwitch "Switch$($Switch.Name)" {
                        Name                   = $Switch.Name
                        Type                   = $Switch.Type
                        Ensure                 = 'Present'
                        DependsOn              = ('[WindowsFeature]Hyper-V', '[WindowsFeature]Hyper-V-PowerShell')
                    }

                } elseif ($Switch.Type -ieq 'Internal') {
                    throw ('Hyper-V Virtual Switch of type {0} has not been implemented yet' -f $Switch.Type)
                }
            }
            #endregion
 
            #region DNS
            $ManagementAdapter = $Node.Roles.Hypervisor.VirtualAdapters.Management
            xDNSServerAddress DNS {
                InterfaceAlias         = $ManagementAdapter.InterfaceAlias
                AddressFamily          = 'IPV4'
                Address                = $ManagementAdapter.DnsServers
                DependsOn              = '[xIPAddress]AdapterAddressManagement'
            }
            #endregion

            #region Adapter
            foreach ($AdapterName in $RoleHypervisor.VirtualAdapters.Keys) {
                $Adapter = $RoleHypervisor.VirtualAdapters.$AdapterName

                cVMNetworkAdapter "Adapter$AdapterName" {
                    Name                   = $AdapterName
                    SwitchName             = $Adapter.SwitchName
                    ManagementOS           = $true
                    Ensure                 = 'Present'
                    DependsOn              = "[cVMSwitch]Switch$($Adapter.SwitchName)"
                }

                cVMNetworkAdapterSettings "AdapterSettings$AdapterName" {
                    Name                   = $AdapterName
                    SwitchName             = $Node.SwitchName
                    ManagementOS           = $true
                    MinimumBandwidthWeight = $Adapter.Weight
                    DependsOn              = ("[cVMSwitch]Switch$($Adapter.SwitchName)", "[cVMNetworkAdapter]Adapter$AdapterName")
                }
 
                if ($Adapter.VlanId -gt 0) {
                    cVMNetworkAdapterVlan "AdapterVlan$AdapterName" {
                        Name                   = $AdapterName
                        ManagementOS           = $true
                        AdapterMode            = 'Access'
                        VlanId                 = $Adapter.VlanId
                        DependsOn              = ("[cVMSwitch]Switch$($Adapter.SwitchName)", "[cVMNetworkAdapter]Adapter$AdapterName")
                    }
                }
 
                xIPAddress "AdapterAddress$AdapterName" {
                    InterfaceAlias         = $Adapter.InterfaceAlias
                    AddressFamily          = 'IPV4'
                    IPAddress              = $Adapter.IPAddress
                    SubnetMask             = $Adapter.SubnetMask
                    DependsOn              = "[cVMNetworkAdapter]Adapter$AdapterName"
                }
            }
            #endregion

            #region Virtual Machine
            foreach ($VmNode in $AllNodes.where{$_.Roles.VirtualMachine}) {
                $RoleVirtualMachine = $Node.Roles.VirtualMachine
                $VmName = $VmNode.Roles.Computer.MachineName
                $VmSwitchName = $VmNode.Roles.VirtualMachine.SwitchName
                $VmBasePath = (Join-Path -Path $RoleHypervisor.StorageBasePath -ChildPath $VmName)
                $VhdxTemplateName = $VmNode.Roles.VirtualMachine.VhdxTemplateName

                #region VHDX Copy
                File ('VhdxCopy_' + $VmName) {
                    Ensure          = 'Present'
                    Type            = 'File'
                    SourcePath      = (Join-Path -Path $RoleHypervisor.VhdxTemplatePath -ChildPath $VhdxTemplateName)
                    DestinationPath = (Join-Path -Path $VmBasePath -ChildPath $VhdxTemplateName)
                    Force           = $True
                }
                #endregion

                #region Hyper-V VM
                $StartupMemory = 512MB
                if ($VmNode.Roles.VirtualMachine.StartupMemory) {
                    $StartupMemory = $VmNode.Roles.VirtualMachine.StartupMemory
                }
                $MinimumMemory = 512MB
                if ($VmNode.Roles.VirtualMachine.MinimumMemory) {
                    $MinimumMemory = $VmNode.Roles.VirtualMachine.MinimumMemory
                }
                $MaximumMemory = 2048MB
                if ($VmNode.Roles.VirtualMachine.MaximumMemory) {
                    $MaximumMemory = $VmNode.Roles.VirtualMachine.MaximumMemory
                }
                $ProcessorCount = 2
                if ($VmNode.Roles.VirtualMachine.ProcessorCount) {
                    $ProcessorCount = $VmNode.Roles.VirtualMachine.ProcessorCount
                }
                $State = 'Off'
                if ($VmNode.Roles.VirtualMachine.State) {
                    $State = $VmNode.Roles.VirtualMachine.State
                }
 
                xVMHyperV ('NewVm_' + $VmName) {
                    Ensure          = 'Present'
                    Generation      = 'vhdx'
                    StartupMemory   = $StartupMemory
                    MinimumMemory   = $MinimumMemory
                    MaximumMemory   = $MaximumMemory
                    MACAddress      = $VmNode.Roles.VirtualMachine.MACAddress
                    Path            = (Join-Path -Path $RoleHypervisor.StorageBasePath -ChildPath $VmName)
                    ProcessorCount  = $ProcessorCount
                    RestartIfNeeded = $True
                    State           = $State
                    SwitchName      = $VmSwitchName
                    Name            = $VmName
                    VHDPath         = (Join-Path -Path $VmBasePath -ChildPath $VhdxTemplateName)
                    DependsOn       = (('[File]VhdxCopy_' + $VmName), ('[xVMSwitch]' + $VmSwitchName))
                }
                #endregion
            }
            #endregion
        }
        #endregion

        #region Roles DomainController
        if ($Node.Roles.Keys -icontains 'FirstDomainController' -Or $Node.Roles.Keys -icontains 'AdditionalDomainController') {
            WindowsFeature AD-Domain-Services {
                Ensure    = 'Present'
                Name      = 'AD-Domain-Services'
            }
            
            WindowsFeature RSAT-AD-PowerShell {
                Ensure    = 'Present'
                Name      = 'RSAT-AD-PowerShell'
            }
            
            WindowsFeature RSAT-ADDS-Tools {
                Ensure    = 'Present'
                Name      = 'RSAT-ADDS-Tools'
            }
        }

        #region Role FirstDomainController
        if ($Node.Roles.Keys -icontains 'FirstDomainController') {
            $RoleFirstDc = $Node.Roles.FirstDomainController
            
            xADDomain 'FirstDc_$($RoleFirstDc.DomainName)' {
                DomainName                    = $RoleFirstDc.DomainName
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleFirstDc.Credentials])
                SafemodeAdministratorPassword = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleFirstDc.Credentials])
                #DnsDelegationCredential       = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleFirstDc.Credentials])
                DependsOn                     = ('[WindowsFeature]AD-Domain-Services', '[WindowsFeature]RSAT-AD-PowerShell', '[WindowsFeature]RSAT-ADDS-Tools')
            }

            xWaitForADDomain 'ForestWait_$($RoleFirstDc.DomainName)' {
                DomainName           = $RoleFirstDc.DomainName
                DomainUserCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleFirstDc.Credentials])
                RetryCount           = $RoleFirstDc.RetryCount
                RetryIntervalSec     = $RoleFirstDc.RetryIntervalSec
                DependsOn            = '[xADDomain]FirstDc_$($RoleFirstDc.DomainName)'
            }
        }
        #endregion

        #region Role AdditionalDomainController
        if ($Node.Roles.Keys -icontains 'AdditionalDomainController') {
            $RoleNextDc = $Node.Roles.AdditionalDomainController
            
            xWaitForADDomain 'ForestWait_$($RoleNextDc.DomainName)' {
                DomainName           = $RoleNextDc.DomainName
                DomainUserCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleNextDc.Credential])
                RetryCount           = $RoleNextDc.RetryCount
                RetryIntervalSec     = $RoleNextDc.RetryIntervalSec
            }

            xADDomainController 'NextDc$($RoleNextDc.DomainName)' {
                DomainName                    = $RoleNextDc.DomainName
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleNextDc.Credential])
                SafemodeAdministratorPassword = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleNextDc.Credential])
                DependsOn                     = ('[xWaitForADDomain]ForestWait_$($RoleNextDc.DomainName)', '[WindowsFeature]AD-Domain-Services', '[WindowsFeature]RSAT-AD-PowerShell', '[WindowsFeature]RSAT-ADDS-Tools')
            }
        }
        #endregion
        #endregion

        #region Roles SQL
        if ($Node.Roles.Keys -icontains 'SqlStandalone' -Or $Node.Roles.Keys -icontains 'SqlMgmtTools') {
            File SxS_Copy {
                Ensure          = 'Present'
                SourcePath      = $ConfigurationData.Environment.WindowsSource + '\sources\SxS'
                Type            = 'Directory'
                Recurse         = $True
                DestinationPath = 'C:\Windows\Temp\SxS'
                Credential      = (Import-Clixml -Path $ConfigurationData.Credentials[$ConfigurationData.Environment.WindowsSourceCredentials])
            }

            <#Package SxS_Fix {
                Name = 'KB3005628'
                Path = $ConfigurationData.Environment.WindowsSource + '\..\Windows8.1-KB2966828-x64.msu'
                ProductId = ''
                Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$ConfigurationData.Environment.WindowsSourceCredentials])
                Ensure = 'Present'
            }#>

            WindowsFeature NET-Framework-Core {
                Ensure     = 'Present'
                Name       = 'NET-Framework-Core'
                Source     = 'C:\Windows\Temp\SxS'
                DependsOn  = ('[xComputer]ComputerNameAndDomainJoin', '[File]SxS_Copy'<#, '[Package]SxS_Fix'#>)
            }
        }

        #region Role SQL Server
        if ($Node.Roles.Keys -icontains 'SqlStandalone') {
            $RoleSql = $Node.Roles.SqlStandalone
            $NodeComputer = $Node.Roles.Computer

            <#xADUser ('Service-Sql-' + $RoleSql.InstanceName) {
                DomainName                    = $NodeComputer.DomainName
                DomainAdministratorCredential = $NodeComputer.Credentials
                UserName                      = 'Service-Sql-' + $RoleSql.InstanceName
                Password                      = $RoleSql.ServicePassword
                Ensure                        = 'Present'
            }#>
            
            xSqlServerSetup ('SqlSetup_' + $RoleSql.InstanceName) {
                InstanceName        = $RoleSql.InstanceName
                PID                 = $RoleSql.ProductKey
                SetupCredential     = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Setup])
                SourcePath          = $RoleSql.SourcePath
                AgtSvcAccount       = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Agent])
                ErrorReporting      = 'False'
                Features            = $RoleSql.Features
                SecurityMode        = 'SQL'
                SAPwd               = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_SA])
                SQLCollation        = $RoleSql.Collation
                SQLSvcAccount       = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Agent])
                SQLSysAdminAccounts = $RoleSql.Admins + $RoleSql.Admins
                #SourceFolder         = ''
                #SQMReporting        = 'False'
                #UpdateEnabled       = 'True'
                #UpdateSource        = 'MU'
                #InstallSharedDir    = ''
                #InstallSharedWOWDir = ''
                #InstallSQLDataDir   = ''
                #InstanceDir         = ''
                #SQLTempDBDir         = ''
                #SQLTempDBLogDir      = ''
                #SQLUserDBDir         = ''
                #SQLUserDBLogDir      = ''
                #SQLBackupDir         = ''
                DependsOn            = ('[WindowsFeature]NET-Framework-Core'<#, '[xADUser]Service-Sql-' + $RoleSql.InstanceName#>)
            }

            xSqlServerFirewall ('SqlFirewall' + $RoleSql.InstanceName) {
                SourcePath   = $RoleSql.SourcePath
                InstanceName = $RoleSql.InstanceName
                Features     = $RoleSql.Features
                DependsOn    = ('[xSqlServerSetup]SqlSetup_' + $RoleSql.InstanceName)
            }
        }
        #endregion

        #region Role SqlMgmtTools
        if ($Node.Roles.Keys -icontains 'SqlMgmtTools') {
            $RoleSql = $ConfigurationData.Roles.SqlMgmtTools
            $RoleSql = $Node.Roles.SqlMgmtTools
            
            xSqlServerSetup SQLMT {
                SourcePath      = $RoleSql.SourcePath
                SetupCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Setup])
                InstanceName    = 'NULL'
                Features        = 'SSMS,ADV_SSMS'
                DependsOn       = '[WindowsFeature]NET-Framework-Core'
            }
        }
        #endregion
        #endregion

    }#End Node
}#End Configuration