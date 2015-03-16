@{
    NodeName              = '0f45d854-94b9-469d-97f6-ab269320f92a'
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