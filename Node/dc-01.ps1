@{
    NodeName                    = '0f45d854-94b9-469d-97f6-ab269320f92a'
    PsDscAllowPlaintextPassword = 'true'
    Roles = @{
        Computer              = @{
            MachineName = 'dc-01'
        }
        VirtualMachine        = @{
            SwitchName       = 'Datacenter'
            State            = 'Running'
            VhdxTemplateName = 'HyperV_Gen2_WS12R2U1_20150929_Core.vhdx'
            StartupMemory    = 512MB
            MinimumMemory    = 512MB
            MaximumMemory    = 2048MB
            ProcessorCount   = 2
        }
        FirstDomainController = @{
            DomainName  = 'inmylab.de'
            RetryCount       = 3
            RetryIntervalSec = 10
            Credentials = 'administrator@inmylab.de'
        }
    }
}