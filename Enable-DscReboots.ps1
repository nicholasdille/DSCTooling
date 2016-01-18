Configuration EnableDscReboots {

    Node 'localhost' {

        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
    }
}

EnableDscReboots -OutputPath "$PSScriptRoot\Output"
Set-DscLocalConfigurationManager -Path "$PSScriptRoot\Output" -Verbose