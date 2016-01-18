$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = 'sql-01'
            PSDscAllowPlainTextPassword  = $true
            Roles = @{
                Computer = @{
                    MachineName = 'sql-01'
                    DomainName  = 'inmylab.de'
                    Credential  = 'administrator@inmylab.de'
                    #DnsServer   = '10.0.0.112'
                    #Adapter     = 'Ethernet'
                }
                OUs = @(
                    <#@{
                        Name = 'Groups'
                        DomainName = 'inmylab.de'
                        Path = 'OU=LAB,DC=inmylab,DC=de'
                        DomainAdministratorCredential = 'administrator@inmylab.de'
                    }#>
                    @{
                        Name = 'Permissions'
                        DomainName = 'inmylab.de'
                        Path = 'OU=Groups,OU=LAB,DC=inmylab,DC=de'
                        DomainAdministratorCredential = 'administrator@inmylab.de'
                        DependsOn = '[xADOrganizationalUnit]GroupsOU'
                    }
                )
                Groups = @(
                    @{
                        Name        = 'DG-Admin-SQL01'
                        Description = 'Local administrators of database server SQL-01 from trusted domains'
                        Category    = 'Security'
                        Scope       = 'DomainLocal'
                        Path        = 'OU=Permissions,OU=Groups,OU=LAB,DC=inmylab,DC=de'
                        Credential  = $Node.Roles.Computer.Credential
                        DependsOn   = '[xADOrganizationalUnit]Permissions'
                    }
                    @{
                        Name        = 'GG-Admin-SQL01'
                        Description = 'Local administrators of database server SQL-01 from local domain'
                        Category    = 'Security'
                        Scope       = 'DomainLocal'
                        Path        = 'OU=Permissions,OU=Groups,OU=LAB,DC=inmylab,DC=de'
                        Credential  = $Node.Roles.Computer.Credential
                        DependsOn   = '[xADOrganizationalUnit]Permissions'
                    }
                    @{
                        Name        = 'DG-Admin-PrimaryDatabaseService'
                        Description = 'Service administrators of database service from trusted domains'
                        Category    = 'Security'
                        Scope       = 'DomainLocal'
                        Path        = 'OU=Permissions,OU=Groups,OU=LAB,DC=inmylab,DC=de'
                        Credential  = $Node.Roles.Computer.Credential
                        DependsOn   = '[xADOrganizationalUnit]Permissions'
                    }
                    @{
                        Name        = 'GG-Admin-PrimaryDatabaseService'
                        Description = 'Service administrators of database service from local domain'
                        Category    = 'Security'
                        Scope       = 'DomainLocal'
                        Path        = 'OU=Permissions,OU=Groups,OU=LAB,DC=inmylab,DC=de'
                        Credential  = $Node.Roles.Computer.Credential
                        DependsOn   = '[xADOrganizationalUnit]Permissions'
                    }
                )
                LocalGroups = @(
                    @{
                        Name       = 'Administrators'
                        Members    = 'DG-Admin-SQ01'
                        Credential = 'administrator@inmylab.de'
                        DependsOn  = '[xADGroup]DG-Admin-SQ01'
                    }
                )
                Membership = @(
                    @{
                        DomainName             = 'inmylab.de'
                        GroupName              = 'DG-Admin-SQL01'
                        Members                = ('GG-Admin-SQL01')
                        AllowAdditionalMembers = $true
                        Credential             = 'administrator@inmylab.de'
                    }
                    @{
                        DomainName             = 'inmylab.de'
                        GroupName              = 'DG-Admin-PrimaryDatabaseService'
                        Members                = ('GG-Admin-PrimaryDatabaseService')
                        AllowAdditionalMembers = $true
                        Credential             = 'administrator@inmylab.de'
                    }
                )
                SqlStandalone = @{
                    InstanceName     = 'MSSQLSERVER'
                    Credential_Agent = 'Srv-Sql-MSSQLSERVER@inmylab.de'
                    Credential_SA    = 'sa@sql-01'
                    Admins           = ('LAB\DG-Admin-PrimaryDatabaseService')
                    SourcePath       = 'e:'
                    Credential_Setup = 'administrator@inmylab.de'
                    Features         = 'SQLENGINE'
                    Collation        = $null
                }
                SqlMgmtTools = @{
                    SourcePath       = 'e:'
                    Credential_Setup = 'administrator@inmylab.de'
                }
            }
        }
    )
    Credentials = @{
        'administrator@inmylab.de' = (Join-Path -Path $PSScriptRoot -ChildPath 'administrator@inmylab.de.clixml')
        'Srv-Sql-MSSQLSERVER@inmylab.de' = (Join-Path -Path $PSScriptRoot -ChildPath 'Srv-Sql-MSSQLSERVER@inmylab.de.clixml')
        'sa@sql-01' = (Join-Path -Path $PSScriptRoot -ChildPath 'sa@sql-01.clixml')

    }
    Environment = @{
        WindowsSource = 'd:'
        WindowsSourceCredentials = 'administrator@inmylab.de'
    }
}
