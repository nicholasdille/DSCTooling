Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'Test_NestedConfig_WindowsFeature.psm1')

Configuration MyConfig {
    Node 'localhost' {
        Ensure_WindowsFeature Test {
            Name = 'Hyper-V-PowerShell'
        }
    }
}

# this does not work
# corresponding feedback on connect: https://connect.microsoft.com/PowerShell/feedback/details/812942/dsc-failure-to-pass-parameters-to-nested-configurations
# only solution available today is creating a composite resource: http://getpocket.com/redirect?url=http%3A%2F%2Fblogs.msdn.com%2Fb%2Fpowershell%2Farchive%2F2014%2F02%2F25%2Freusing-existing-configuration-scripts-in-powershell-desired-state-configuration.aspx
MyConfig -OutputPath (Join-Path -Path $PSScriptRoot -ChildPath 'Temp')