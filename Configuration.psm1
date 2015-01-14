Configuration LabConfiguration {
    param()

    #region Import resources
    Import-DSCResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName xComputerManagement
    Import-DscResource -ModuleName xHyper-V
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xRemoteDesktopAdmin
    Import-DscResource -ModuleName xSqlServer
    Import-DscResource -ModuleName xNetworking
    #endregion
 
    Node $AllNodes.NodeName {

        #region Computer
        if ($Node.Roles.Keys -icontains 'Computer') {
            $NodeComputer = $Node.Roles.Computer

            if ($NodeComputer.containsKey('DomainName') -And -Not $NodeComputer.containsKey('Credentials')) {
                Write-Error 'Error in ConfigData: You specified DomainName without Credentials'
            }
            
            if ($NodeComputer.containsKey('DomainName') -And $NodeComputer.containsKey('Credentials')) {
                if ($NodeComputer.containsKey('DnsServer') -And $NodeComputer.containsKey('Adapter')) {
                    xDNSServerAddress DNS {
                        Address        = ($NodeComputer.DnsServer)
                        InterfaceAlias = $NodeComputer.Adapter
                        AddressFamily  = 'IPv4'
                    }
                }

                if ($NodeComputer.containsKey('MachineName')) {
                    xComputer RenameComputerAndJoinDomain {
                        Name       = $NodeComputer.MachineName
                        DomainName = $NodeComputer.DomainName
                        Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credentials])
                        DependsOn  = ('[xDNSServerAddress]DNS')
                    }

                } else {
                    xComputer JoinDomain {
                        DomainName = $NodeComputer.DomainName
                        Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credentials])
                        DependsOn  = ('[xDNSServerAddress]DNS')
                    }
                }

            } else {
                xComputer RenameComputer {
                    Name       = $NodeComputer.MachineName
                }
            }
        }
        #endregion

        #region Remote Desktop
        xRemoteDesktopAdmin RDP {
            Ensure = 'Present'
            UserAuthentication = 'Secure'
        }
        #endregion

        #region Wave Deployment
        <#File WaveDeploy_Copy {
            Ensure = 'Present'
            SourcePath = '\\demo.dille.name\storage\install\Microsoft\Desired State Configuration\DSC Resource Kit Wave 8 10282014.zip'
            DestinationPath = 'C:\Windows\Temp'
            Credential = (Import-Clixml -Path $ConfigurationData.Credentials['administrator@demo.dille.name'])
        }

        Archive WaveDeploy_Unpack {
            Ensure = 'Present'
            Path = 'C:\Windows\Temp\DSC Resource Kit Wave 8 10282014.zip'
            Destination = 'C:\Program Files\WindowsPowerShell\Modules'
            DependsOn = '[File]WaveDeploy_Copy'
        }#>
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
                    
            #region Virtual Switch
            foreach ($VirtualSwitch in $RoleHypervisor.VirtualSwitches) {
                xVMSwitch $VirtualSwitch.Name {
                    Ensure            = 'Present'
                    Name              = $VirtualSwitch.Name
                    Type              = $VirtualSwitch.Type
                    NetAdapterName    = $VirtualSwitch.NetAdapterName
                    AllowManagementOS = $VirtualSWitch.AllowManagementOS
                    DependsOn         = ('[WindowsFeature]Hyper-V', '[WindowsFeature]Hyper-V-PowerShell')
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
            WindowsFeature NET-Framework-Core {
                Ensure = 'Present'
                Name   = 'NET-Framework-Core'
                Source = $ConfigurationData.Environment.WindowsSource + '\source\SxS'
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

        #region LocalConfigurationManager

        #region PullClient
        if ($Node.Roles.Keys -icontains 'PullClient') {
            $PullConfig = $ConfigurationData.MetaConfig.PullClient

            LocalConfigurationManager {
                ConfigurationID                = $Node.NodeName
                CertificateId                  = $Node.CertificateThumbprint
                ConfigurationModeFrequencyMins = $PullConfig.ConfigurationModeFrequencyMins
                ConfigurationMode              = $PullConfig.ConfigurationMode
                RebootNodeIfNeeded             = $PullConfig.RebootNodeIfNeeded
                RefreshMode                    = $PullConfig.RefreshMode
                RefreshFrequencyMins           = $PullConfig.RefreshFrequencyMins
                DownloadManagerName            = $PullConfig.DownloadManagerName
                DownloadManagerCustomData      = $PullConfig.DownloadManagerCustomData
                AllowModuleOverwrite           = $PullConfig.AllowModuleOverwrite
            }
        }
        #endregion

        #region PullClientDebug
        if ($Node.Roles.Keys -icontains 'PullClientDebug') {
            $PullConfig = $ConfigurationData.MetaConfig.PullClientDebug

            LocalConfigurationManager {
                ConfigurationID                = $Node.NodeName
                CertificateId                  = $Node.CertificateThumbprint
                ConfigurationModeFrequencyMins = $PullConfig.ConfigurationModeFrequencyMins
                ConfigurationMode              = $PullConfig.ConfigurationMode
                RebootNodeIfNeeded             = $PullConfig.RebootNodeIfNeeded
                RefreshMode                    = $PullConfig.RefreshMode
                RefreshFrequencyMins           = $PullConfig.RefreshFrequencyMins
                DownloadManagerName            = $PullConfig.DownloadManagerName
                DownloadManagerCustomData      = $PullConfig.DownloadManagerCustomData
                AllowModuleOverwrite           = $PullConfig.AllowModuleOverwrite
            }
        }
        #endregion

        #region PushClient
        if ($Node.Roles.Keys -icontains 'PushClient') {
            $PushConfig = $ConfigurationData.MetaConfig.PushClient

            LocalConfigurationManager {
                ConfigurationID                = $Node.NodeName
                CertificateId                  = $Node.CertificateThumbprint
                ConfigurationMode              = $PushConfig.ConfigurationMode
                RebootNodeIfNeeded             = $PushConfig.RebootNodeIfNeeded
                RefreshFrequencyMins           = $PushConfig.RefreshFrequencyMins
                ConfigurationModeFrequencyMins = $PushConfig.ConfigurationModeFrequencyMins
            }
        }
        #endregion
        #endregion

    }#End Node
}#End Configuration