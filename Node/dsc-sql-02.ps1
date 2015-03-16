@{
    NodeName              = '45bfc046-9cd1-4057-9f6e-2fac334be85d'
    Roles = @{
        Computer              = @{
            MachineName = 'dsc-sql-02'
            DomainName  = 'demo.dille.name'
            Credentials = 'administrator@demo.dille.name'
        }
        PullClient            = @{}
        SqlStandalone = @{
            InstanceName     = 'MSSQLSERVER'
            #ServicePassword  = '43}G4t6Kp7hg:Wj'
            Credential_Agent = 'Service-Sql@demo.dille.name'
            Credential_SA    = 'sa@dsc-sql-01' # ???
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