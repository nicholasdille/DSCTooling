function Get-CredentialFromStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialStore = $PSDSC_CredPath
    )

    Import-Clixml -Path (Join-Path -Path $CredentialStore -ChildPath ($CredentialName + '.clixml'))
}

function New-CredentialInStore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]
        $Credential
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialStore = $PSDSC_CredPath
    )

    $Credential | Export-Clixml -Path (Join-Path -Path $CredentialStore -ChildPath ($CredentialName + '.clixml'))
}