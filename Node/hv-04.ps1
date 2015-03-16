@{
    NodeName              = 'bcef580e-da00-447b-a4f7-8e84d430de2d'
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
        PullClient = @{}
    }
}