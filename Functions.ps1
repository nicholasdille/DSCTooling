function New-PsRemoteSession {
    [CmdletBinding()]
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
        ,
        [Parameter(Mandatory=$false)]
        [switch]
        $UseCredSsp
    )

    if ($UseCredSsp -And -Not $CredentialName) {
        throw 'When using CredSSP credentials must be specified. Aborting.'
    }

    $params = @{}
                           $params.Add('ComputerName',    $ComputerName)
    if ($CredentialName) { $params.Add('Credential',      (Get-CredentialFromStore -CredentialName $CredentialName)) }
    if ($UseCredSsp)     { $params.Add('Authentication', 'Credssp') }

    $PsSession = New-PSSession @params
    if (-Not $PsSession) {
        throw ('Failed to create PowerShell remote session to <{0}>. Aborting.' -f $ComputerName)
    }

    $PsSession
}

function Enter-PsRemoteSession {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
        ,
        [Parameter(Mandatory=$false,ParameterSetName='Computer')]
        [switch]
        $UseCredSsp
        ,
        [Parameter(Mandatory=$true,ParameterSetName='PsSession')]
        [ValidateNotNullOrEmpty()]
        #[PSSession]
        $PsSession
    )

    if (-Not $PsSession) {
        $PsSession = New-PsRemoteSession @PSBoundParameters
    }
    Enter-PSSession -Session $PsSession
}

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

function Get-VmIdFromHyperV {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    (Get-VM @PSBoundParameters | Select Id).Id
}

function Get-VmIdFromVmm {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$VMMServer
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    (Get-SCVirtualMachine @PSBoundParameters | Select Id).Id
}

function Get-VmIp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VmName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $IPv4Pattern = '^\d+\.\d+\.\d+\.\d+$'
    )

    (Get-VM -ComputerName $ComputerName -Name $VmName).NetworkAdapters[0].IPAddresses | Where-Object { $_ -match $IPv4Pattern } | Select-Object -First 1
}

function Convert-RemoteFilePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $FilePath
        ,
        [string]
        $ComputerName = $env:COMPUTERNAME
        ,
        [string]
        $DomainName = $env:USERDNSDOMAIN
    )

    $FilePath -imatch '^(\w)\:\\' | Out-Null
    $FilePath.Replace($Matches[0], '\\' + $ComputerName + '.' + $DomainName + '\' + $Matches[1] + '$\')
}

function Copy-VMFileRemotely {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false,ParameterSetName='Computer')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
        ,
        [Parameter(Mandatory=$true,ParameterSetName='PsSession')]
        [ValidateNotNullOrEmpty()]
        #[PSSession]
        $PsSession
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VmName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Files
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DestinationPath
    )

    if (-Not $PsSession) {
        $params = @{
            ComputerName   = $ComputerName
            CredentialName = $CredentialName
            UseCredSsp     = $True
        }
        $PsSession = New-PsRemoteSession @params
    }

    Invoke-Command -Session $PsSession -ScriptBlock {
        foreach ($File in $Using:Files) {
            Copy-VMFile $Using:VmName -SourcePath $File -DestinationPath $Using:DestinationPath -CreateFullPath -FileSource Host -Force
        }
    }
}