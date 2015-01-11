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
        Get-DscLocalConfigurationManager -ComputerName $ComputerName -Credential (Get-CredentialFromStore -CredentialName $CredentialName)

    } else {
        Get-DscLocalConfigurationManager -ComputerName $ComputerName
    }
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
        Get-DscConfiguration -ComputerName $ComputerName -Credential (Get-CredentialFromStore -CredentialName $CredentialName)

    } else {
        Get-DscConfiguration -ComputerName $ComputerName
    }
}