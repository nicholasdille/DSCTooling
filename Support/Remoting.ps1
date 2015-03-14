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
        [System.Management.Automation.Runspaces.PSSession]
        $Session
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

    if (-Not $Session) {
        $params = @{
            ComputerName   = $ComputerName
            CredentialName = $CredentialName
            UseCredSsp     = $True
        }
        $Session = New-PsRemoteSession @params
    }

    Invoke-Command -Session $Session -ScriptBlock {
        foreach ($File in $Using:Files) {
            Copy-VMFile $Using:VmName -SourcePath $File -DestinationPath $Using:DestinationPath -CreateFullPath -FileSource Host -Force
        }
    }
}

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

    $Session = New-PSSession @params
    if (-Not $Session) {
        throw ('Failed to create PowerShell remote session to <{0}>. Aborting.' -f $ComputerName)
    }

    $Session
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
        [System.Management.Automation.Runspaces.PSSession]
        $Session
    )

    if (-Not $Session) {
        $Session = New-PsRemoteSession @PSBoundParameters
    }
    Enter-PSSession -Session $Session
}

function Copy-ToRemoteItem {
    param(
        $SourcePath
        ,
        $ComputerName
        ,
        $DestinationPath
        ,
        $Credential
    )

    $SourceData = Get-Content -Path $SourcePath -Encoding Byte
    $SourceDataBase64 = [System.Convert]::ToBase64String($SourceData)
    Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
        [System.Convert]::FromBase64String($Using:SourceDataBase64) | Set-Content -Path $Using:DestinationPath -Encoding Byte
    }
}

function Copy-FromRemoteItem {
    param(
        $SourcePath
        ,
        $ComputerName
        ,
        $DestinationPath
        ,
        $Credential
    )

    $SourceDataBase64 = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
        $SourceData = Get-Content -Path $Using:SourcePath -Encoding Byte
        [System.Convert]::ToBase64String($SourceData)
    }
    [System.Convert]::FromBase64String($SourceDataBase64) | Set-Content -Path $DestinationPath -Encoding Byte
}