function Publish-DscConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
    )

    Get-ChildItem -Path "$PSDSC_OutputPath" | Where-Object { $_.Name -imatch '^(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\.mof(\.checksum)?$' } | foreach {
        Copy-Item -Path "$($_.FullName)" -Destination ('\\{0}\c$\Program Files\WindowsPowershell\DscService\Configuration' -f $ComputerName) -Force
    }
}

function Push-DscConfig {
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

function New-Certificate {
    [CmdletBinding()]
    param()

    $NewCertHostName = 'hv-05'
    $NewCertCn       = ('{0}.demo.dille.name' -f $NewCertHostName)

    $CertReqInfFile = Join-Path -Path $PSScriptRoot -ChildPath ('Cert\{0}_Req.inf' -f $NewCertHostName)
    $CertReqFile    = Join-Path -Path $PSScriptRoot -ChildPath ('Temp\{0}_Req.req' -f $NewCertHostName)
    $CertFile       = Join-Path -Path $PSScriptRoot -ChildPath ('Cert\{0}.cer' -f $NewCertHostName)
    $CertRspFile    = Join-Path -Path $PSScriptRoot -ChildPath ('Temp\{0}_File.rsp' -f $NewCertHostName)
    $CertPfxFile    = Join-Path -Path $PSScriptRoot -ChildPath ('Cert\{0}.pfx' -f $NewCertHostName)
    $CertThumbFile  = Join-Path -Path $PSScriptRoot -ChildPath ('Cert\{0}.txt' -f $NewCertHostName)
    $CredCertFile   = Join-Path -Path $PSScriptRoot -ChildPath 'Cred\Certificate.clixml'

    if (Test-Path -Path $CertReqFile) {
        Remove-Item -Path $CertReqFile
    }
    if (Test-Path -Path $CertFile) {
        Remove-Item -Path $CertFile
    }
    if (Test-Path -Path $CertFile) {
        Remove-Item -Path $CertFile
    }

    # create request
    certreq.exe -new $CertReqInfFile $CertReqFile

    # submit request
    certreq.exe -config DC-01\demo-CA -submit $CertReqFile $CertFile

    # import certificate
    certreq.exe -accept $CertFile

    # retrieve certificate thumbprint
    $NewCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -icontains $NewCertCn }
    $NewCertThumb = $NewCert.Thumbprint

    # Export certificate to pfx
    Export-PfxCertificate -Cert $NewCert -FilePath $CertPfxFile -Password (Import-Clixml -Path $CredCertFile).Password

    # Extract thumbprint
    (Get-PfxData -FilePath C:\Users\administrator.DEMO\OneDrive\Scripts\DSC\Cert\contoso-dc-01.pfx -Password (Import-Clixml -Path $CredCertFile).Password).EndEntityCertificates.Thumbprint | Set-Content -Path CertThumbFile
}

function Set-VmConfiguration {
    [CmdletBinding()]
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
    Copy-VMFileRemotely -ComputerName $VmHost -Credential (Import-Clixml -Path $DomainCredFile) -VmName $VmName -Files $Files -DestinationPath $LocalBasePath

    $Vm = Get-VM -ComputerName $VmHost -Name $VmName
    $VmIp = $Vm.NetworkAdapters[0].IPAddresses | Where-Object { $_ -match $IPv4Pattern } | Select-Object -First 1
    $CertPass = (Import-Clixml -Path $CertCredFile)
    Invoke-Command -ComputerName $VmIp -Credential (Import-Clixml -Path $LocalCredFile) -ScriptBlock {
        Get-ChildItem $Using:LocalBasePath\*.cer | foreach { Import-Certificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\Root | Out-Null }
        Get-ChildItem $Using:LocalBasePath\*.pfx | foreach { Import-PfxCertificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\My -Password $Using:CertPass | Out-Null }
        Get-ChildItem $Using:LocalBasePath\*.meta.mof | Where-Object { $_.BaseName -notmatch 'localhost.meta.mof' } | Select-Object -First 1 | Rename-Item -NewName localhost.meta.mof -ErrorAction SilentlyContinue

        Set-DscLocalConfigurationManager -Path $Using:LocalBasePath -ComputerName localhost
    }
}

function Convert-DscMetaConfigurations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    
    Get-ChildItem -Path $Path | Where-Object { $_.Name -imatch '\.meta\.mof$' } | foreach {
        Convert-DscMetaConfiguration -MofFullName $_.FullName
    }
}

function Convert-DscMetaConfiguration {
    [CmdletBinding()]
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