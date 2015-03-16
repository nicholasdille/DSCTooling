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
            Teams = @(
                @{
                    Name                   = 'Team.Datacenter'
                    Adapters               = ('Ethernet0', 'Ethernet1 2')
                    TeamingMode            = 'SwitchIndependent'
                    LoadBalancingAlgorithm = 'HyperVPort'
                }
            )
            VirtualSwitches = @(
                @{
                    Name              = 'Switch.Datacenter'
                    Type              = 'External'
                    Adapter           = 'Team.Datacenter'
                }
                @{
                    Name              = 'Switch.Schulung1'
                    Type              = 'Private'
                }
            )
            VirtualAdapters        = @{
                Management         = @{
                    InterfaceAlias = 'vEthernet (Management)'
                    VlanId         = 0
                    Weight         = 20
                    IPAddress      = '10.0.0.154'
                    SubnetMask     = 24
                    DefaultGateway = '10.0.0.1'
                    DnsServers     = ('10.0.0.2')
                }
                LiveMigration      = @{
                    InterfaceAlias = 'vEthernet (LiveMigration)'
                    VlanId         = 10
                    Weight         = 30
                    IPAddress      = '10.0.1.154'
                    SubnetMask     = 24
                }
            }

        }
    }
}