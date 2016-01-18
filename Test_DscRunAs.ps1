$ConfigData = @{
    AllNodes = @(
        @{
            NodeName = 'localhost'
            PsDscAllowPlainTextPassword = $true
        }
    )
}

Configuration TestDscRunAs {
    Import-DscResource –ModuleName ’PSDesiredStateConfiguration’

    Node $AllNodes.NodeName {    
        Script Test {
            PsDscRunAsCredential = (Get-Credential -Message 'Test')
            GetScript = ‘@{}’
            TestScript = ‘$false’
            SetScript = {whoami | Set-Content -Path \\srv2\install\temp\test.txt}
        } #Script

        Script Test2 {
            PsDscRunAsCredential = (Get-Credential -Message 'Test2')
            GetScript = ‘@{}’
            TestScript = ‘$false’
            SetScript = {whoami | Set-Content -Path \\srv2\install\temp\test2.txt}
        } #Script
    } #Node

} #Configuration

TestDscRunAs -OutputPath .\Output -ConfigurationData $ConfigData