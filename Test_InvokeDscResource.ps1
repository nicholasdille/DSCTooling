Invoke-DscResource -Name cRDSessionDeployment -Method Test -Property @{
    SessionHost = 'RDS-02'
    WebAccess   = 'RDS-02'
    Credential  = Import-Clixml -Path (Join-Path -Path $PSScriptRoot -ChildPath 'administrator@DEMO.clixml')
}