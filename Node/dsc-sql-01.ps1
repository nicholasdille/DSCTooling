@{
    NodeName              = 'e00cdcb3-db9a-4981-a274-7d000e5c129d'
    Roles = @{
        Computer              = @{
            MachineName = 'dsc-sql-01'
            DomainName  = 'demo.dille.name'
            Credentials = 'administrator@demo.dille.name'
        }
        PullClient            = @{}
        SqlStandalone = @{
            InstanceName     = 'MSSQLSERVER'
            #ServicePassword  = '43}G4t6Kp7hg:Wj'
            Credential_Agent = 'Service-Sql@demo.dille.name'
            Credential_SA    = 'sa@dsc-sql-01'
            Admins           = ('DEMO\Sql-Admins')
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