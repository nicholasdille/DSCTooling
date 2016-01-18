Configuration MasterConfiguration {
    param()

    #region Import resources
    Import-DSCResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xComputerManagement
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
        Write-Verbose 'Processing region Computer'
        if ($Node.Roles.Keys -icontains 'Computer') {
            $NodeComputer = $Node.Roles.Computer

            if ($NodeComputer.containsKey('DomainName') -And -Not $NodeComputer.containsKey('Credential')) {
                Write-Error 'Error in ConfigData: You specified DomainName without Credentials'
            }
            
            if ($NodeComputer.containsKey('DomainName') -And $NodeComputer.containsKey('Credential')) {
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
                        Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credential])
                        DependsOn  = $DependsOn
                    }

                } else {
                    xComputer ComputerNameAndDomainJoin {
                        DomainName = $NodeComputer.DomainName
                        Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credential])
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
        Write-Verbose 'Processing region Base config'
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
        Write-Verbose 'Processing region WindowsFeature'
        foreach ($WindowsFeature in $Node.WindowsFeatures) {
            WindowsFeature $WindowsFeature.Name {
                Ensure    = $WindowsFeature.Ensure
                Name      = $WindowsFeature.Name
                DependsOn = $WindowsFeature.DependsOn
            }
        }
        #endregion

        #region Service
        Write-Verbose 'Processing region Service'
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
        Write-Verbose 'Processing region Registry'
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

        #region Prerequisites for AD operations
        WindowsFeature 'RSAT-AD-PowerShell' {
            Name   = 'RSAT-AD-PowerShell'
            Ensure = 'Present'
        }
        #endregion

        #region AD Organizational Units
        Write-Verbose 'Processing region OU'
        foreach ($OU in $Node.Roles.OUs) {
            xADOrganizationalUnit $OU.Name {
                OUName                        = $OU.Name
                OUPath                        = $OU.Path
                DomainName                    = $OU.DomainName
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$OU.DomainAdministratorCredential])
                Ensure                        = 'Present'
                DependsOn                     = '[WindowsFeature]RSAT-AD-PowerShell', $OU.DependsOn
            }
        }
        #endregion

        #region AD Groups
        Write-Verbose 'Processing region Groups'
        foreach ($Group in $Node.Roles.Groups) {
            xADGroup $Group.Name {
                GroupName  = $Group.Name
                GroupScope = $Group.Scope
                Category   = $Group.Category
                Path       = $Group.Path
                Credential = (Import-Clixml -Path $ConfigurationData.Credentials[$Group.Credential])
                Ensure     = 'Present'
                DependsOn  = '[WindowsFeature]RSAT-AD-PowerShell', $Group.DependsOn
            }
        }
        #endregion

        #region AD Group Membership
        Write-Verbose 'Processing region Group Membership'
        foreach ($Membership in $Node.Roles.Membership) {
            $DependsOn = '[WindowsFeature]RSAT-AD-PowerShell'
            if ($Membership.Keys -icontains 'DependsOn') {
                $DependsOn += $Membership.DependsOn
            }
            xADGroupMembership $Membership.GroupName {
                GroupName              = $Membership.GroupName
                DomainName             = $Membership.DomainName
                Members                = $Membership.Members
                AllowAdditionalMembers = $Membership.AllowAdditionalMembers
                Credential             = (Import-Clixml -Path $ConfigurationData.Credentials[$Membership.Credential])
                Ensure                 = 'Present'
                DependsOn              = $DependsOn
            }
        }
        #endregion

        #region Local Groups
        Write-Verbose 'Processing region Local Groups'
        foreach ($Group in $Node.LocalGroups) {
            Group $Group.Name {
                GroupName  = $Group.Name
                Members    = $Group.Members
                Credential = $Group.Credential
                Ensure     = 'Present'
                DependsOn  = $Group.DependsOn
            }
        }
        #endregion

        #region Roles SQL
        Write-Verbose 'Processing region SQL generic'
        if ($Node.Roles.Keys -icontains 'SqlStandalone' -Or $Node.Roles.Keys -icontains 'SqlMgmtTools') {
            <#File SxS_Copy {
                Ensure          = 'Present'
                SourcePath      = $ConfigurationData.Environment.WindowsSource + '\sources\SxS'
                Type            = 'Directory'
                Recurse         = $True
                DestinationPath = 'C:\Windows\Temp\SxS'
                Credential      = (Import-Clixml -Path $ConfigurationData.Credentials[$ConfigurationData.Environment.WindowsSourceCredentials])
            }#>

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
                #Source     = 'C:\Windows\Temp\SxS'
                Source     = $ConfigurationData.Environment.WindowsSource + '\sources\SxS'
                DependsOn  = ('[xComputer]ComputerNameAndDomainJoin'<#, '[File]SxS_Copy'<#, '[Package]SxS_Fix'#>)
            }
        }

        #region Role SQL Server
        Write-Verbose 'Processing region SQL role'
        if ($Node.Roles.Keys -icontains 'SqlStandalone') {
            $RoleSql = $Node.Roles.SqlStandalone
            $NodeComputer = $Node.Roles.Computer

            xADOrganizationalUnit 'LabOU' {
                DomainName = $NodeComputer.DomainName
                OUName = 'LAB'
                OUPath = 'DC=inmylab,DC=de'
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credential])
                DependsOn = '[WindowsFeature]RSAT-AD-PowerShell'
            }

            xADOrganizationalUnit 'GroupsOU' {
                DomainName = $NodeComputer.DomainName
                OUName = 'Groups'
                OUPath = 'OU=LAB,DC=inmylab,DC=de'
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credential])
                DependsOn = '[WindowsFeature]RSAT-AD-PowerShell', '[xADOrganizationalUnit]LabOU'
            }

            xADOrganizationalUnit 'RolesOU' {
                DomainName = $NodeComputer.DomainName
                OUName = 'Roles'
                OUPath = 'OU=Groups,OU=LAB,DC=inmylab,DC=de'
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credential])
                DependsOn = '[WindowsFeature]RSAT-AD-PowerShell', '[xADOrganizationalUnit]GroupsOU'
            }

            $ServiceAccount = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Agent])
            xADUser 'ServiceAccount' {
                DomainName                    = $NodeComputer.DomainName
                DomainAdministratorCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$NodeComputer.Credential])
                UserName                      = ($ServiceAccount.UserName -split '\\')[1]
                Password                      = $ServiceAccount
                Ensure                        = 'Present'
                DependsOn                     = '[WindowsFeature]RSAT-AD-PowerShell', '[xADOrganizationalUnit]RolesOU'
            }
            
            xSqlServerSetup ('SqlSetup_' + $RoleSql.InstanceName) {
                InstanceName        = $RoleSql.InstanceName
                PID                 = $RoleSql.ProductKey
                SetupCredential     = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Setup])
                SourcePath          = $RoleSql.SourcePath
                SourceFolder        = ''
                AgtSvcAccount       = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Agent])
                ErrorReporting      = 'False'
                Features            = $RoleSql.Features
                SecurityMode        = 'SQL'
                SAPwd               = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_SA])
                SQLCollation        = $RoleSql.Collation
                SQLSvcAccount       = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Agent])
                SQLSysAdminAccounts = $RoleSql.Admins
                UpdateEnabled       = 'False'
                UpdateSource        = 'MU'
                #SQMReporting        = 'False'
                #InstallSharedDir    = ''
                #InstallSharedWOWDir = ''
                #InstallSQLDataDir   = ''
                #InstanceDir         = ''
                #SQLTempDBDir         = ''
                #SQLTempDBLogDir      = ''
                #SQLUserDBDir         = ''
                #SQLUserDBLogDir      = ''
                #SQLBackupDir         = ''
                DependsOn            = ('[WindowsFeature]NET-Framework-Core', '[xADUser]ServiceAccount')
            }

            xSqlServerFirewall ('SqlFirewall' + $RoleSql.InstanceName) {
                SourcePath   = $RoleSql.SourcePath
                SourceFolder = ''
                InstanceName = $RoleSql.InstanceName
                Features     = $RoleSql.Features
                DependsOn    = ('[xSqlServerSetup]SqlSetup_' + $RoleSql.InstanceName)
            }
        }
        #endregion

        #region Role SqlMgmtTools
        Write-Verbose 'Processing region SQL tools'
        if ($Node.Roles.Keys -icontains 'SqlMgmtTools') {
            $RoleSql = $ConfigurationData.Roles.SqlMgmtTools
            $RoleSql = $Node.Roles.SqlMgmtTools
            
            xSqlServerSetup SQLMT {
                SourcePath      = $RoleSql.SourcePath
                SourceFolder    = ''
                SetupCredential = (Import-Clixml -Path $ConfigurationData.Credentials[$RoleSql.Credential_Setup])
                InstanceName    = 'NULL'
                Features        = 'SSMS,ADV_SSMS'
                UpdateEnabled   = 'False'
                UpdateSource    = 'MU'
                DependsOn       = '[WindowsFeature]NET-Framework-Core'
            }
        }
        #endregion
        #endregion

    }#End Node
}#End Configuration