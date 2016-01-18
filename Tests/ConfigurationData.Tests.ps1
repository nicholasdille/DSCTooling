. "$PSScriptRoot\ConfigurationData.ps1"
$AllNodes = $ConfigurationData.AllNodes

Describe 'Structural Tests' {
    It 'Defines credential files' {
        $ConfigurationData.Keys -icontains 'Credentials' | Should Be $true
    }
    foreach ($CredName in $ConfigurationData.Credentials.Keys) {
        It "Defines existing credential file for $CredName" {
            Test-Path -Path $ConfigurationData.Credentials.$CredName | Should Be $true
        }
    }
    It 'Defines environmental data' {
        $ConfigurationData.Keys -icontains 'Environment' | Should Be $true
    }
}

foreach ($Node in $ConfigurationData.AllNodes) {
    Describe "Node $($Node.NodeName)" {
        Context 'Role computer' {
            It 'Resolves credential object if specified' {
                if ($Node.Roles.Keys -icontains 'Computer' -and $Node.Roles.Computer -icontains 'Credential') {
                    $ConfigurationData.Credentials -icontains $Node.Roles.Computer.Credential | Should Be $true
                }
            }
        }

        Context 'Active Directory Organizational Units' {
            if ($Node.Roles.Keys -icontains 'OUs') {
                foreach ($OU in $Node.Roles.OUs) {
                    It "Defines existings credential file for $($OU.DomainAdministratorCredential)" {
                        Test-Path -Path $ConfigurationData.Credentials[$OU.DomainAdministratorCredential] | Should Be $true
                    }
                }
            }
        }

        Context 'Active Directory Groups' {
            if ($Node.Roles.Keys -icontains 'Groups') {
                foreach ($Group in $Node.Roles.Groups) {
                    if ($Group.Keys -icontains 'Credential') {
                        It "Defines existings credential file for $($Group.Credential)" {
                            Test-Path -Path $ConfigurationData.Credentials[$Group.Credential] | Should Be $true
                        }
                    }
                }
            }
        }

        Context 'Local Groups' {
            if ($Node.Roles.Keys -icontains 'LocalGroups') {
                foreach ($Group in $Node.Roles.LocalGroups) {
                    It "Defines existings credential file for $($Group.Credential)" {
                        Test-Path -Path $ConfigurationData.Credentials[$Group.Credential] | Should Be $true
                    }
                }
            }
        }

        Context 'Role database server' {
            It 'Resolves SQL Server agent credential object if specified' {
                if ($Node.Roles.Keys -icontains 'SqlStandalone' -and $Node.Roles.SqlStandalone -icontains 'Credential_Agent') {
                    $ConfigurationData.Credentials -icontains $Node.Roles.SqlStandalone.Credential | Should Be $true
                }
            }
            It 'Resolves SQL Server SA credential object if specified' {
                if ($Node.Roles.Keys -icontains 'SqlStandalone' -and $Node.Roles.SqlStandalone -icontains 'Credential_SA') {
                    $ConfigurationData.Credentials -icontains $Node.Roles.SqlStandalone.Credential | Should Be $true
                }
            }
            It 'Resolves SQL Server setup credential object if specified' {
                if ($Node.Roles.Keys -icontains 'SqlStandalone' -and $Node.Roles.SqlStandalone -icontains 'Credential_Setup') {
                    $ConfigurationData.Credentials -icontains $Node.Roles.SqlStandalone.Credential | Should Be $true
                }
            }
        }
    }
}