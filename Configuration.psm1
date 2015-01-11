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
                xDNSServerAddress DNS {
                    Address        = ('10.0.0.112')
                    InterfaceAlias = 'Ethernet 3'
                    AddressFamily  = 'IPv4'
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
        <#xRemoteDesktopAdmin RDP {
            Ensure = 'Present'
            UserAuthentication = 'Secure'
        }#>
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
        foreach ($RoleName in $Node.Roles.Keys) {
            if ($ConfigurationData.Roles[$RoleName].WindowsFeatures) {
                foreach ($WindowsFeature in $ConfigurationData.Roles[$RoleName].WindowsFeatures) {
                    WindowsFeature $WindowsFeature.Name {
                        Ensure    = $WindowsFeature.Ensure
                        Name      = $WindowsFeature.Name
                        DependsOn = $WindowsFeature.DependsOn
                    }
                }
            }
        }
        #endregion

        #region Service
        foreach ($RoleName in $Node.Roles.Keys) {
            if ($ConfigurationData.Roles[$RoleName].Services) {
                foreach ($Service in $ConfigurationData.Roles[$RoleName].Services) {
                    Service $Service.Name {
                        Name        = $Service.Name
                        StartupType = $Service.StartupType
                        State       = $Service.State
                        DependsOn   = $Service.DependsOn
                    }
                }
            }
        }
        #endregion
                
        #region Registry
        foreach ($RoleName in $Node.Roles.Keys) {
            if ($ConfigurationData.Roles[$RoleName].RegistrySettings) {
                foreach ($RegistrySetting in $ConfigurationData.Roles[$RoleName].RegistrySettings) {
                    Registry $RegistrySetting.ValueName {
                        Ensure    = $RegistrySetting.Ensure
                        Key       = $RegistrySetting.Key
                        ValueName = $RegistrySetting.ValueName
                        ValueType = $RegistrySetting.ValueType
                        ValueData = $RegistrySetting.ValueData
                        DependsOn = $RegistrySetting.DependsOn
                    }
                }
            }
        }
        #endregion

        #region Role PullServer
        if ($Node.Roles.Keys -icontains 'PullServer') {
            $PullConfig = $ConfigurationData.Roles.PullServer
            $NodePullConfig = $Node.Roles.PullServer

            $CertificateThumbPrint = 'AllowUnencryptedTraffic'
            if ($NodePullConfig.containsKey('CertificateThumbPrint')) {
                $CertificateThumbPrint = $NodePullConfig.CertificateThumbprint
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
            $RoleHypervisor = $ConfigurationData.Roles.Hypervisor
                    
            #region Virtual Switch
            foreach ($VirtualSwitch in $RoleHypervisor.VirtualSwitches) {
                xVMSwitch $VirtualSwitch.Name {
                    Ensure            = $VirtualSwitch.Ensure
                    Name              = $VirtualSwitch.Name
                    Type              = $VirtualSwitch.Type
                    NetAdapterName    = $VirtualSwitch.NetAdapterName
                    AllowManagementOS = $VirtualSWitch.AllowManagementOS
                    DependsOn         = $VirtualSWitch.DependsOn
                }
            }
            #endregion

            #region Virtual Machine
            foreach ($VmNode in $AllNodes.where{ $_.Roles.VirtualMachine }) {
                $RoleVirtualMachine = $ConfigurationData.Roles.VirtualMachine
                $VmName = $VmNode.Roles.Computer.MachineName
                $VmBasePath = (Join-Path -Path $RoleHypervisor.StorageBasePath -ChildPath $VmName)
                $VhdxTemplateName = $VmNode.Roles.VirtualMachine.VhdxTemplateName

                #region VHDX Copy
                File "VhdxCopy_$VmName" {
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
 
                xVMHyperV "NewVm_$VmName" {
                    Ensure          = 'Present'
                    Generation      = 'vhdx'
                    StartupMemory   = $StartupMemory
                    MinimumMemory   = $MinimumMemory
                    MaximumMemory   = $MaximumMemory
                    MACAddress      = $VmNode.Roles.VirtualMachine.MACAddress
                    Path            = (Join-Path -PAth $RoleHypervisor.StorageBasePath -ChildPath $VmName)
                    ProcessorCount  = $ProcessorCount
                    RestartIfNeeded = $True
                    State           = $State
                    SwitchName      = $RoleVirtualMachine.SwitchName
                    Name            = $VmName
                    VHDPath         = (Join-Path -Path $VmBasePath -ChildPath $VhdxTemplateName)
                    DependsOn       = ("[File]VhdxCopy_$VmName", "[xVMSwitch]$($RoleVirtualMachine.SwitchName)")
                }
                #endregion
            }
            #endregion
        }
        #endregion

        #region Role FirstDomainController
        if ($Node.Roles.Keys -icontains 'FirstDomainController') {
            $RoleFirstDc = $ConfigurationData.Roles.FirstDomainController
            $NodeFirstDc = $Node.Roles.FirstDomainController
            
            xADDomain "FirstDc_$($NodeFirstDc.DomainName)" {
                DomainName                    = $NodeFirstDc.DomainName
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeFirstDc.Credentials])
                SafemodeAdministratorPassword = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeFirstDc.Credentials])
                #DnsDelegationCredential       = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeFirstDc.Credentials])
                DependsOn                     = ('[WindowsFeature]AD-Domain-Services', '[WindowsFeature]RSAT-AD-PowerShell', '[WindowsFeature]RSAT-ADDS-Tools')
            }

            xWaitForADDomain "ForestWait_$($RoleFirstDc.DomainName)" {
                DomainName           = $NodeFirstDc.DomainName
                DomainUserCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeFirstDc.Credentials])
                RetryCount           = $RoleFirstDc.RetryCount
                RetryIntervalSec     = $RoleFirstDc.RetryIntervalSec
                DependsOn            = "[xADDomain]FirstDc_$($NodeFirstDc.DomainName)"
            }
        }
        #endregion

        #region Role AdditionalDomainController
        if ($Node.Roles.Keys -icontains 'AdditionalDomainController') {
            $RoleNextDc = $ConfigurationData.Roles.AdditionalDomainController
            $NodeNextDc = $Node.Roles.AdditionalDomainController
            
            xWaitForADDomain "ForestWait_$($RoleNextDc.DomainName)" {
                DomainName           = $RoleNextDc.DomainName
                DomainUserCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeNextDc.Credential])
                RetryCount           = $RoleNextDc.RetryCount
                RetryIntervalSec     = $RoleNextDc.RetryIntervalSec
            }

            xADDomainController "NextDc$($RoleNextDc.DomainName)" {
                DomainName                    = $RoleNextDc.DomainName
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeNextDc.Credential])
                SafemodeAdministratorPassword = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeNextDc.Credential])
                DependsOn                     = "[xWaitForADDomain]ForestWait_$($RoleNextDc.DomainName)"
            }
        }
        #endregion

        #region Role SQL Server
        if ($Node.Roles.Keys -icontains 'SqlStandalone') {
            $RoleSql = $ConfigurationData.Roles.SqlStandalone
            $NodeSql = $Node.Roles.SqlStandalone
            $NodeComputer = $Node.Roles.Computer

            <#xADUser ('Service-Sql-' + $NodeSql.InstanceName) {
                DomainName                    = $NodeComputer.DomainName
                DomainAdministratorCredential = $NodeComputer.Credentials
                UserName                      = 'Service-Sql-' + $NodeSql.InstanceName
                Password                      = $NodeSql.ServicePassword
                Ensure                        = 'Present'
            }#>
            
            xSqlServerSetup ('SqlSetup_' + $NodeSql.InstanceName) {
                InstanceName        = $NodeSql.InstanceName
                PID                 = $RoleSql.ProductKey
                SetupCredential     = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Setup])
                SourcePath          = $RoleSql.SourcePath
                AgtSvcAccount       = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeSql.Credential_Agent])
                ErrorReporting      = 'False'
                Features            = $RoleSql.Features
                SecurityMode        = 'SQL'
                SAPwd               = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeSql.Credential_SA])
                SQLCollation        = $RoleSql.Collation
                SQLSvcAccount       = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeSql.Credential_Agent])
                SQLSysAdminAccounts = $RoleSql.Admins + $NodeSql.Admins
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
                DependsOn            = ('[WindowsFeature]NET-Framework-Core'<#, '[xADUser]Service-Sql-' + $NodeSql.InstanceName#>)
            }

            xSqlServerFirewall ('SqlFirewall' + $NodeSql.InstanceName) {
                SourcePath   = $RoleSql.SourcePath
                InstanceName = $NodeSql.InstanceName
                Features     = $RoleSql.Features
                DependsOn    = ('[xSqlServerSetup]SqlSetup_' + $NodeSql.InstanceName)
            }
        }
        #endregion

        if ($Node.Roles.Keys -icontains 'SqlMgmtTools') {
            $RoleSql = $ConfigurationData.Roles.SqlMgmtTools
            $NodeSql = $Node.Roles.SqlMgmtTools
            
            xSqlServerSetup SQLMT {
                SourcePath      = $RoleSql.SourcePath
                SetupCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeSql.Credential_Setup])
                InstanceName    = 'NULL'
                Features        = 'SSMS,ADV_SSMS'
                DependsOn       = '[WindowsFeature]NET-Framework-Core'
            }
        }

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