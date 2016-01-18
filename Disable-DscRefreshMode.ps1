[DSCLocalConfigurationManager()]
Configuration DisableDscRefreshMode {

    Node 'localhost' {

        Settings {
            RefreshMode = 'Disabled'
        }
    }
}

DisableDscRefreshMode -OutputPath "$PSScriptRoot\Output"
Set-DscLocalConfigurationManager -Path "$PSScriptRoot\Output" -Verbose