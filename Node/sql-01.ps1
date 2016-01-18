@{
    NodeName              = '1ca1728d-f336-4772-bfa1-90b4758fc7f9'
    Roles = @{
        VirtualMachine        = @{
            SwitchName       = 'Datacenter'
            State            = 'Running'
            VhdxTemplateName = 'HyperV_Gen2_WS12R2U1_20150929_Core.vhdx'
            StartupMemory    = 512MB
            MinimumMemory    = 512MB
            MaximumMemory    = 2048MB
            ProcessorCount   = 2
        }
        Computer              = @{
            MachineName = 'sql-01'
            DomainName  = 'inmylab.de'
            Credentials = 'administrator@inmylab.de'
            DnsServer   = '10.0.0.112'
            Adapter     = 'Ethernet 3'
        }
        # domain local group for local administrators 
        # domain local group for instance administrators
        SqlStandalone = @{
            InstanceName     = 'MSSQLSERVER'
            #ServicePassword  = '43}G4t6Kp7hg:Wj'
            Credential_Agent = 'Service-Sql-MSSQLSERVER@inmylab.de'
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