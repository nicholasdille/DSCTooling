function Assert-PathVariable {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VariableName
        ,
        [Parameter(Mandatory=$false)]
        [switch]
        $CheckOnly
    )

    Assert-Variable -VariableName $VariableName
    $VariableValue = Get-Variable -Name $VariableName -ValueOnly

    if (-Not (Test-Path -Path $VariableValue)) {
        if ($CheckOnly) {
            Write-Error ('Path <{0}> specified in variable <{1}> does not exist. Aborting.' -f $VariableValue,$VariableName)
            throw

        } else {
            New-Item -ItemType Directory -Path $VariableValue
        }
    }
}

function Assert-Variable {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VariableName
    )

    if (-Not (Get-Variable -Name $VariableName -ValueOnly -ErrorAction SilentlyContinue)) {
        Write-Error ('Variable <{0}> is not defined. Aborting.' -f $VariableName)
        throw
    }
}

function Assert-BasePath {
    Assert-PathVariable -VariableName PSDSC_BasePath
}

function Assert-OutputPath {
    Assert-PathVariable -VariableName PSDSC_OutputPath
}

function Clear-OutputPath {
    Assert-OutputPath
    Get-ChildItem "$PSDSC_OutputPath" | foreach {
        Remove-Item -Path "$($_.FullName)" -Force
    }
}

function Publish-DscConfig {
}

function Invoke-DscConfig {
    . $PSDSC_DataFile
    Import-Module $PSDSC_ConfigFile

    Assert-OutputPath
    Clear-OutputPath

    Write-Verbose 'LabConfiguration'
    LabConfiguration -OutputPath $PSDSC_OutputPath -ConfigurationData $ConfigData

    New-DscCheckSum -ConfigurationPath $PSDSC_OutputPath
    Get-ChildItem -Path "$PSDSC_OutputPath" | where { $_.Name -imatch '^(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\.mof(\.checksum)?$' } | foreach {
        Copy-Item -Path "$($_.FullName)" -Destination "\\hv-04\c`$\Program Files\WindowsPowershell\DscService\Configuration" -Force
    }
}

function Push-DscConfig {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = (Get-Location)
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $CredentialName
    )
    Assert-BasePath

    if ($CredentialName) {
        Start-DscConfiguration -ComputerName $ComputerName -Path $Path -Wait -Verbose -Credential (Get-CredentialFromStore -CredentialName $CredentialName)

    } else {
        Start-DscConfiguration -ComputerName $ComputerName -Path $Path -Wait -Verbose
    }
}

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

function Get-CredentialFromStore {
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

function Set-VmConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $VmHost
        ,
        [Parameter(Mandatory=$true)]
        [string]
        $VmName
        ,
        [Parameter(Mandatory=$true)]
        [string]
        $NodeGuid
        ,
        [Parameter(Mandatory=$false)]
        [string]
        $DomainCredName = 'administrator@demo.dille.name'
        ,
        [Parameter(Mandatory=$false)]
        [string]
        $LocalCredName = 'administrator@WIN-xxxxxxxx'
        ,
        [Parameter(Mandatory=$false)]
        [string]
        $RootCaName = 'demo-CA'
        ,
        [Parameter(Mandatory=$false)]
        [string]
        $LocalBasePath = 'c:\dsc'
        ,
        [Parameter(Mandatory=$false)]
        [string]
        $IPv4Pattern = '^\d+\.\d+\.\d+\.\d+$'
    )
    
    $DomainCredFile = Join-Path -Path $PSDSC_CredPath   -ChildPath ($DomainCredName + '.clixml')
    $CertFile       = Join-Path -Path $PSDSC_CertPath   -ChildPath ($VmName + '.pfx')
    $MetaFile       = Join-Path -Path $PSDSC_OutputPath -ChildPath ($NodeGuid + '.meta.mof')

    $LocalCredFile  = Join-Path -Path $PSDSC_CredPath   -ChildPath ($LocalCredName + '.clixml')
    $CertCredFile   = Join-Path -Path $PSDSC_CredPath   -ChildPath 'Certificates.clixml'
    $CaFile         = Join-Path -Path $PSDSC_CertPath   -ChildPath ($RootCaName + '.cer')

    Enable-VMIntegrationService -ComputerName $VmHost -VMName $VmName -Name 'Guest Service Interface'

    $Files = $($CertFile, $MetaFile, $CaFile)
    $Files = foreach ($File in $Files) {
        $File -imatch '^(\w)\:\\' | Out-Null
        $File.Replace($Matches[0], '\\' + $env:COMPUTERNAME + '.' + $env:USERDNSDOMAIN + '\' + $Matches[1] + '$\')
    }
    Invoke-Command -ComputerName $VmHost -Authentication Credssp -Credential (Import-Clixml -Path $DomainCredFile) -ScriptBlock {
        foreach ($File in $Using:Files) {
            Copy-VMFile $Using:VmName -SourcePath $File -DestinationPath $Using:LocalBasePath -CreateFullPath -FileSource Host -Force
        }
    }

    $Vm = Get-VM -ComputerName $VmHost -Name $VmName
    $VmIp = $Vm.NetworkAdapters[0].IPAddresses | where { $_ -match $IPv4Pattern }
    $CertPass = (Import-Clixml -Path $CertCredFile)
    Invoke-Command -ComputerName $VmIp -Credential (Import-Clixml -Path $LocalCredFile) -ScriptBlock {
        Get-ChildItem $Using:LocalBasePath\*.cer | foreach { Import-Certificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\Root | Out-Null }
        Get-ChildItem $Using:LocalBasePath\*.pfx | foreach { Import-PfxCertificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\My -Password $Using:CertPass | Out-Null }
        Get-ChildItem $Using:LocalBasePath\*.meta.mof | where { $_.BaseName -notmatch 'localhost.meta.mof' } | select -First 1 | Rename-Item -NewName localhost.meta.mof -ErrorAction SilentlyContinue

        Set-DscLocalConfigurationManager -Path $Using:LocalBasePath -ComputerName localhost
    }
}

function ConvertTo-EncryptedString {
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
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [Security.SecureString]
        $SecureString
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

function Strip-DscMetaConfigurations {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    
    Get-ChildItem -Path $Path | where { $_.Name -imatch '\.meta\.mof$' } | foreach {
        Strip-DscMetaConfiguration -MofFullName $_.FullName
    }
}

function Strip-DscMetaConfiguration {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MofFullName
    )
    
    $IncludeLine = $True
    $MofContent = Get-Content -Path $_.FullName | foreach {
        $Line = $_

        #Write-Verbose ('Line: {0}' -f $Line)

        if ($Line -match '^instance of ') {
            #Write-Verbose ('  IncludeLine = {0}' -f $IncludeLine)
            $IncludeLine = $False
        }
        if ($Line -match '^instance of (MSFT_DSCMetaConfiguration|MSFT_KeyValuePair)') {
            #Write-Verbose ('  IncludeLine = {0}' -f $IncludeLine)
            $IncludeLine = $True
        }

        if ($IncludeLine) {
            #Write-Verbose '  SHOW'
            $Line
        }
    }
    $MofContent | Set-Content -Path $_.FullName
}

function Get-VmIdFromHyperV {
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
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$VMMServer
        ,[Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    (Get-SCVirtualMachine @PSBoundParameters | Select Id).Id
}