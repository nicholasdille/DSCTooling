[DSCLocalConfigurationManager()]
Configuration PrepareLcm {

    Node 'localhost' {

        Settings {
            RefreshMode = 'Disabled'
            DebugMode   = 'ForceModuleImport'
        }
    }
}

PrepareLcm -OutputPath "$PSScriptRoot\OutputPath"
Set-DscLocalConfigurationManager -Path "$PSScriptRoot\OutputPath" -Verbose