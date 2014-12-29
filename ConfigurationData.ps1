$ConfigData = @{
    AllNodes = @(
        @{
            NodeName              = 'hv-04'
            CertificateThumbprint = 'cc70984bb677bfd158ebffe47a2f22e3d5c10d8f'
            CertificateFile       = (Join-Path -Path $PSScriptRoot -ChildPath 'Cert\hv-04.cer')
            Roles = @{
                Computer = @{
                    MachineName = 'hv-04'
                    DomainName  = 'demo.dille.name'
                    Credentials = 'administrator@demo.dille.name'
                }
                Hypervisor = @{}
                PushClient = @{}
                PullServer = @{
                    CertificateThumbprint = 'cc70984bb677bfd158ebffe47a2f22e3d5c10d8f'
                }
            }
        }
        @{
            NodeName              = '9565b711-30c2-43d5-a929-2167955733d3'
            CertificateThumbprint = 'a6e1b663d7cadcb62d49a59bde903e07f9b999be'
            CertificateFile       = (Join-Path -Path $PSScriptRoot -ChildPath 'Cert\contoso-dc-01.cer')
            Roles = @{
                Computer              = @{
                    MachineName = 'contoso-dc-01'
                }
                VirtualMachine        = @{
                    State            = 'Off'
                    VhdxTemplateName = 'HyperV_Gen2_WS12R2U1_20140915.vhdx'
                    StartupMemory    = 512MB
                    MinimumMemory    = 512MB
                    MaximumMemory    = 2048MB
                    ProcessorCount   = 2
                    #MACAddress       = ''
                }
                PullClient            = @{}
                FirstDomainController = @{
                    DomainName  = 'contoso.com'
                    Credentials = 'administrator@contoso.com'
                }
            }
        }
        @{
            NodeName              = '1ca1728d-f336-4772-bfa1-90b4758fc7f9'
            CertificateThumbprint = ''
            CertificateFile       = (Join-Path -Path $PSScriptRoot -ChildPath 'Cert\contoso-sql-01.cer')
            Roles = @{
                Computer              = @{
                    MachineName = 'contoso-sql-01'
                    DomainName  = 'contoso.com'
                    Credentials = 'administrator@contoso.com'
                }
                VirtualMachine        = @{
                    State            = 'Off'
                    VhdxTemplateName = 'HyperV_Gen2_WS12R2U1_20140915.vhdx'
                    StartupMemory    = 512MB
                    MinimumMemory    = 512MB
                    MaximumMemory    = 2048MB
                    ProcessorCount   = 2
                    #MACAddress       = ''
                }
                PullClient            = @{}
                SqlStandalone = @{
                    InstanceName     = 'MSSQLSERVER'
                    #ServicePassword  = '43}G4t6Kp7hg:Wj'
                    Credential_Agent = 'Service-Sql-MSSQLSERVER@contoso.com'
                    Admins           = ('CONTOSO\Sql-Admins')
                }
            }
        }
    )

    Credentials = @{
        'administrator@demo.dille.name'       = (Join-Path -Path $PSScriptRoot -ChildPath 'Cred\administrator@demo.dille.name.clixml')
        'administrator@contoso.com'           = (Join-Path -Path $PSScriptRoot -ChildPath 'Cred\administrator@contoso.com.clixml')
        'Service-Sql-MSSQLSERVER@contoso.com' = (Join-Path -Path $PSScriptRoot -ChildPath 'Cred\Service-Sql-MSSQLSERVER@contoso.com.clixml')
    }

    MetaConfig = @{
        PullClient = @{
            AllowModuleOverwrite           = $True
            ConfigurationModeFrequencyMins = 6
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded             = $True
            RefreshMode                    = 'PULL'
            RefreshFrequencyMins           = 2
            DownloadManagerName            = 'WebDownloadManager'
            #DownloadManagerCustomData      = @{ServerUrl = 'https://hv-04.demo.dille.name:8080/PSDSCPullServer/PSDSCPullServer.svc'}
            DownloadManagerCustomData      = @{ServerUrl = 'http://hv-04.demo.dille.name:8081/PSDSCPullServer/PSDSCPullServer.svc'; AllowUnsecureConnection = 'True'}
        }
        PushClient = @{
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded             = $True
            RefreshMode                    = 'PULL'
            RefreshFrequencyMins           = 2
            ConfigurationModeFrequencyMins = 6
        }
    }

    Roles = @{
        VirtualMachine = @{
            SwitchName = 'Datacenter'
        }
        PullServer = @{
            PullPort = 8080
            CompliancePort = 9080
            WindowsFeatures = @(
                @{ Ensure = 'Present'; Name = 'DSC-Service' }
                @{ Ensure = 'Present'; Name = 'Web-Mgmt-Service' }
            )
            Services = @(
                @{ Name = 'WMSVC'; StartupType = 'Automatic'; State = 'Running'; DependsOn = '[WindowsFeature]Web-Mgmt-Service' }
            )
            RegistrySettings = @(
                @{
                    Ensure    = 'Present'
                    Key       = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server'
                    ValueName = 'EnableRemoteManagement'
                    ValueType = 'Dword'
                    ValueData = '1'
                    DependsOn = ('[WindowsFeature]Web-Mgmt-Service', '[Service]WMSVC')
                }
            )
        }
        Hypervisor = @{
            VhdxTemplatePath = '\\demo.dille.name\storage\VMM_Library\VHD'
            StorageBasePath  = '\\demo.dille.name\storage\VMM_Storage'
            WindowsFeatures  = @(
                @{ Ensure = 'Present'; Name = 'Hyper-V' }
                @{ Ensure = 'Present'; Name = 'Hyper-V-PowerShell' }
            )
            RegistrySettings = @()
            VirtualSwitches = @(
                @{
                    Ensure            = 'Present'
                    Name              = 'Datacenter'
                    Type              = 'External'
                    NetAdapterName    = 'Ethernet0'
                    AllowManagementOS = $True
                    DependsOn         = '[WindowsFeature]Hyper-V'
                }
            )
        }
        FirstDomainController = @{
            RetryCount       = 3
            RetryIntervalSec = 10
            WindowsFeatures = @(
                @{ Ensure = 'Present'; Name = 'AD-Domain-Services' }
                @{ Ensure = 'Present'; Name = 'RSAT-AD-PowerShell' }
                @{ Ensure = 'Present'; Name = 'RSAT-ADDS-Tools' }
            )
        }
        AdditionalDomainController = @{
            RetryCount       = 3
            RetryIntervalSec = 10
            WindowsFeatures = @(
                @{ Ensure = 'Present'; Name = 'AD-Domain-Services' }
                @{ Ensure = 'Present'; Name = 'RSAT-AD-PowerShell' }
                @{ Ensure = 'Present'; Name = 'RSAT-ADDS-Tools' }
            )
        }
        SqlStandalone = @{
            SourcePath       = '\\demo.dille.name\storage\install\Microsoft\SQL Server 2012\SQL2012'
            Credential_Setup = 'administrator@demo.dille.name'
            Features         = 'SQLENGINE'
            Collation        = $null
            #Admins           = ('', '')
            WindowsFeatures = @(
                @{ Ensure = 'Present'; Name = 'NET-Framework-Core' }
            )
        }
        SqlMgmtTools = @{
            SourcePath = '\\demo.dille.name\storage\install\Microsoft\SQL Server 2012\SQL2012'
            WindowsFeatures = @(
                @{ Ensure = 'Present'; Name = 'NET-Framework-Core'; Source = '\\demo.dille.name\storage\install\Microsoft\Windows Server 2012 R2\WS12R2U1NovEN\sources\SxS' }
            )
        }
    }
}