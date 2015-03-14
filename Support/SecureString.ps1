function ConvertTo-EncryptedString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString]
        $SecureString
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Key
    )

    ConvertFrom-SecureString -SecureString $SecureString -Key ([System.Text.Encoding]::ASCII.GetBytes($Key))
}

function ConvertFrom-EncryptedString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $EncryptedString
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Key
    )

    #ConvertTo-SecureString -SecureString $Password -Key ([System.Text.Encoding]::ASCII.GetBytes($Key))
    ConvertTo-SecureString -String $EncryptedString -Key ([System.Text.Encoding]::ASCII.GetBytes($Key))
}

function Get-PlaintextFromSecureString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString]
        $SecureString
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

Function New-Password() {
    [CmdletBinding()]
    Param(
        [int]$Length=10
        ,
        [string[]]$Alphabet
    )

    if (-Not $Alphabet) {
        $Alphabet = $null
        40..126 + 33 + 35..38 | foreach {
            $Alphabet += ,[char][byte]$_
        }
    }

    For ($i = 1; $i –le $Length; $i++) {
        $TempPassword += ($Alphabet | Get-Random)
    }

    return $TempPassword
}