Configuration EnableDscDebugMode {

    Node 'localhost' {

        LocalConfigurationManager {
            DebugMode = 'ForceModuleImport'
        }
    }
}

EnableDscDebugMode -OutputPath "$PSScriptRoot\Output"
Set-DscLocalConfigurationManager -Path "$PSScriptRoot\Output" -Verbose