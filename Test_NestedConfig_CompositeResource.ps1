Configuration MyConfig {

    Import-DscResource -ModuleName cReusableStuff

    Node 'localhost' {

        WindowsFeature Test2 {
            Name = 'Hyper-V'
            Ensure = 'Present'
            #DependsOn = '[cEnsureWindowsFeature]Test'
        }

        cEnsureWindowsFeature Test {
            Name = 'Hyper-V-PowerShell'
            Dependencies = ('[WindowsFeature]Test2')
        }
    }
}

MyConfig -OutputPath (Join-Path -Path $PSScriptRoot -ChildPath 'Temp')