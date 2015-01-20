$ConfigData = @{
    AllNodes = @(
        <#@{
            NodeName              = 'NODENAME'
            CertificateThumbprint = 'THUMBPRINT'
            CertificateFile       = (Join-Path -Path $PSScriptRoot -ChildPath 'Cert\NODENAME.cer')
            Roles = @{}
            WindowsFeatures = @(
                @{ Ensure = 'Present'; Name = 'Hyper-V-PowerShell' }
            )
            Services = @(
                @{ Name = 'WMSVC'; StartupType = 'Automatic'; State = 'Running'; DependsOn = '[WindowsFeature]Web-Mgmt-Service' }
            )
            RegistrySettings = @(
                @{
                    Ensure = 'Present'
                    Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server'
                    ValueName = 'EnableRemoteManagement'
                    ValueType = 'Dword'
                    ValueData = '1'
                    DependsOn = ('[WindowsFeature]Web-Mgmt-Service', '[Service]WMSVC')
                }
            )
        }#>
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
                Hypervisor = @{
                    VhdxTemplatePath = '\\demo.dille.name\storage\VMM_Library\VHD'
                    StorageBasePath  = '\\demo.dille.name\storage\VMM_Storage'
                    VirtualSwitches = @(
                        @{
                            Name              = 'Datacenter'
                            Type              = 'External'
                            NetAdapterName    = 'Ethernet0'
                            AllowManagementOS = $True
                        }
                    )                
                }
                PushClient = @{}
                PullServer = @{
                    PullPort = 8080
                    CompliancePort = 9080
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
                    SwitchName       = 'Datacenter'
                    State            = 'Running'
                    VhdxTemplateName = 'HyperV_Gen2_WS12R2U1_20140915.vhdx'
                    StartupMemory    = 512MB
                    MinimumMemory    = 512MB
                    MaximumMemory    = 2048MB
                    ProcessorCount   = 2
                }
                PullClientDebug      = @{}
                FirstDomainController = @{
                    DomainName  = 'contoso.com'
                    RetryCount       = 3
                    RetryIntervalSec = 10
                    Credentials = 'administrator@contoso.com'
                }
            }
        }
        @{
            NodeName              = '1ca1728d-f336-4772-bfa1-90b4758fc7f9'
            CertificateThumbprint = '2737612A4F20AE4D3AA4079FA7227687DEA9A9A6'
            CertificateFile       = (Join-Path -Path $PSScriptRoot -ChildPath 'Cert\contoso-sql-01.cer')
            Roles = @{
                Computer              = @{
                    MachineName = 'contoso-sql-01'
                    DomainName  = 'contoso.com'
                    Credentials = 'administrator@contoso.com'
                    DnsServer   = '10.0.0.112'
                    Adapter     = 'Ethernet 3'
                }
                VirtualMachine        = @{
                    SwitchName       = 'Datacenter'
                    State            = 'Running'
                    VhdxTemplateName = 'HyperV_Gen2_WS12R2U1_20140915.vhdx'
                    StartupMemory    = 512MB
                    MinimumMemory    = 512MB
                    MaximumMemory    = 2048MB
                    ProcessorCount   = 2
                }
                PullClient            = @{}
                SqlStandalone = @{
                    InstanceName     = 'MSSQLSERVER'
                    #ServicePassword  = '43}G4t6Kp7hg:Wj'
                    Credential_Agent = 'Service-Sql-MSSQLSERVER@contoso.com'
                    Credential_SA    = 'sa@contoso-sql-01'
                    Admins           = ('CONTOSO\Sql-Admins')
                    SourcePath       = '\\demo.dille.name\storage\install\Microsoft\SQL Server 2012\SQL2012'
                    Credential_Setup = 'administrator@demo.dille.name'
                    Features         = 'SQLENGINE'
                    Collation        = $null
                }
                SqlMgmtTools = @{
                    SourcePath       = '\\demo.dille.name\storage\install\Microsoft\SQL Server 2012\SQL2012'
                    Credential_Setup = 'administrator@demo.dille.name'
                }
            }
        }
    )

    Credentials = @{
        'administrator@demo.dille.name'       = (Join-Path -Path $PSScriptRoot -ChildPath 'Cred\administrator@demo.dille.name.clixml')
        'administrator@contoso.com'           = (Join-Path -Path $PSScriptRoot -ChildPath 'Cred\administrator@contoso.com.clixml')
        'Service-Sql-MSSQLSERVER@contoso.com' = (Join-Path -Path $PSScriptRoot -ChildPath 'Cred\Service-Sql-MSSQLSERVER@contoso.com.clixml')
        'sa@contoso-sql-01'                   = (Join-Path -Path $PSScriptRoot -ChildPath 'Cred\sa@contoso-sql-01.clixml')
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
            DownloadManagerCustomData      = @{ServerUrl = 'https://hv-04.demo.dille.name:8080/PSDSCPullServer/PSDSCPullServer.svc'}
            #DownloadManagerCustomData      = @{ServerUrl = 'http://hv-04.demo.dille.name:8081/PSDSCPullServer/PSDSCPullServer.svc'; AllowUnsecureConnection = 'True'}
        }
        PushClient = @{
            ConfigurationMode              = 'ApplyAndAutoCorrect'
            RebootNodeIfNeeded             = $True
            RefreshMode                    = 'PUSH'
            RefreshFrequencyMins           = 2
            ConfigurationModeFrequencyMins = 6
        }
        PullClientDebug = @{
            AllowModuleOverwrite           = $True
            ConfigurationModeFrequencyMins = 6
            ConfigurationMode              = 'ApplyAndMonitor'
            RebootNodeIfNeeded             = $False
            RefreshMode                    = 'PULL'
            RefreshFrequencyMins           = 2
            DownloadManagerName            = 'WebDownloadManager'
            DownloadManagerCustomData      = @{ServerUrl = 'https://hv-04.demo.dille.name:8080/PSDSCPullServer/PSDSCPullServer.svc'}
        }
    }

    Environment = @{
        WindowsSource = '\\demo.dille.name\storage\install\Microsoft\Windows Server 2012 R2\WS12R2U1NovEN'
    }
}