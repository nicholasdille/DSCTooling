function Get-DscMetaConfig {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
    )

    if ($CredentialName) {
        $CimSession = New-CimSession -ComputerName $ComputerName -Credential (Get-CredentialFromStore -CredentialName $CredentialName)

    } else {
        $CimSession = New-CimSession -ComputerName $ComputerName
    }
    if (-Not $CimSession) {
        Write-Error ('Failed to create CIM session to <{0}>. Aborting.' -f $ComputerName)
        throw
    }
    Get-DscLocalConfigurationManager -CimSession $CimSession
}

function Get-DscConfig {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
    )

    if ($CredentialName) {
        $CimSession = New-CimSession -ComputerName $ComputerName -Credential (Get-CredentialFromStore -CredentialName $CredentialName)

    } else {
        $CimSession = New-CimSession -ComputerName $ComputerName
    }
    if (-Not $CimSession) {
        Write-Error ('Failed to create CIM session to <{0}>. Aborting.' -f $ComputerName)
        throw
    }
    Get-DscConfiguration -CimSession $CimSession
}