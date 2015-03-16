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
    )

    $CertCredName   = 'Certificates'
    $CaFile         = Join-Path -Path $PSDSC_CertPath   -ChildPath ($RootCaName + '.cer')
    $CertFile       = Join-Path -Path $PSDSC_CertPath   -ChildPath ($VmName + '.pfx')
    $MetaFile       = Join-Path -Path $PSDSC_OutputPath -ChildPath ($NodeGuid + '.meta.mof')

    Enable-VMIntegrationService -ComputerName $VmHost -VMName $VmName -Name 'Guest Service Interface'

    #$PsSession = New-PsRemoteSession -ComputerName $VmIp -CredentialName $LocalCredName
    $PsSession = New-PsRemoteSession -ComputerName $VmHost -CredentialName $DomainCredName
    Import-Certificates -PsSession $PsSession -VmName $VmName -LocalCredentialName $LocalCredName `
        -RootCertificate (Convert-RemoteFilePath -FilePath $CaFile) `
        -ServerCertificate (Convert-RemoteFilePath -FilePath $CertFile) -ServerCertificateCredentialName $CertCredName
    Set-DscMetaConfig -PsSession $PsSession -VmName $VmName -LocalCredentialName $LocalCredName -MetaConfig (Convert-RemoteFilePath -FilePath $MetaFile)
}

function Import-Certificates {
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
        #[PsSession]
        $PsSession
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VmName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $LocalCredentialName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RootCertificate
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ServerCertificate
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ServerCertificateCredentialName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $LocalBasePath = 'c:\dsc'
    )

    if (-Not $PsSession) {
        $params = $PSBoundParameters
        $params.Remove('MetaConfig')
        $PsSession = New-PsRemoteSession @params
    }
    
    $CertPass = Get-CredentialFromStore -CredentialName $ServerCertificateCredentialName
    Invoke-Command -Session $PsSession -ScriptBlock {
        Get-ChildItem $Using:LocalBasePath\*.cer | foreach { Import-Certificate    -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\Root | Out-Null }
        Get-ChildItem $Using:LocalBasePath\*.pfx | foreach { Import-PfxCertificate -FilePath $_.FullName -CertStoreLocation Cert:\LocalMachine\My -Password $Using:CertPass | Out-Null }
    }

}

function Get-DscResourcesFromTechNet {
    [CmdletBinding()]
    param(
        [string]$ResourceUrlCacheFile = (Join-Path -Path $PSDSC_TempPath -ChildPath 'PSDSC-ResourceDownloader.clixml')
        ,
        [switch]$IgnoreCachedUrls = $false
        ,
        [switch]$OverwriteExistingModules = $false
    )

    if (-Not (Test-Path -Path $ResourceUrlCacheFile) -Or $IgnoreCachedUrls) {
        $ModuleList = New-Object System.Collections.ArrayList

        $PageList = New-Object System.Collections.Stack
        $PageList.Push('https://gallery.technet.microsoft.com/scriptcenter/site/search?f%5B0%5D.Type=Tag&f%5B0%5D.Value=Windows%20PowerShell%20Desired%20State%20Configuration&f%5B0%5D.Text=Windows%20PowerShell%20Desired%20State%20Configuration&pageIndex=1')
        $PageBeenThere = New-Object System.Collections.ArrayList
        while ($PageList.Count -gt 0) {
            $url = $PageList.Pop()
            if (-Not $PageBeenThere.Contains($url)) {
                #'processing {0}' -f $url
                $PageBeenThere.Add($url) | Out-Null
                $page = Invoke-WebRequest $url

                $page.Links | where {$_.href -match 'pageIndex' -and $_.innerText -match '\d+'} | foreach {
                    $url = $_.href
                    $url = $url.Replace('about:', 'https://gallery.technet.microsoft.com')
                    $url = $url.Replace('&amp;', '&')
                    if (-Not $PageBeenThere.Contains($url)) {
                        $PageList.Push($url)
                    }
                }

                $page.Links | where {$_.href -match '^about:/scriptcenter/(.+)-[a-z0-9]{8}$'} | foreach {
                    $url = $_.href
                    $url = $url.Replace('about:', 'https://gallery.technet.microsoft.com')
                    $url = $url.Replace('&amp;', '&')
                    $ModuleList.Push($url)
                }

                Start-Sleep -Seconds 5
            }
        }

        $ModuleList | Export-Clixml -Path $ResourceUrlCacheFile

    } else {
        $ModuleList = Import-Clixml -Path $ResourceUrlCacheFile
    }

    Foreach ($ModuleUrl in $ModuleList) {
        $page = Invoke-WebRequest $ModuleUrl
        $page.Links | where {$_.href -match '^about:/scriptcenter/(.+-[a-z0-9]{8})/file/'} | select -First 1 | foreach {
            $ItemName = $Matches[1]
            $url = $_.href
            $url = $url.Replace('about:', 'https://gallery.technet.microsoft.com')
            $url = $url.Replace('&amp;', '&')
            $url -match '/([^/]+.zip$)' | Out-Null
            $FileName = $Matches[1]
            $FileName = (Join-Path -Path $PSDSC_BasePath -ChildPath ('\DSC-Modules\' + $FileName))
            if (-Not (Test-Path -Path $FileName) -Or $OverwriteExistingModules) {
                Invoke-WebRequest $url -OutFile $FileName
            }
        }
    }
}

function Assert-PathVariable {
    [CmdletBinding()]
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
            throw ('Path <{0}> specified in variable <{1}> does not exist. Aborting.' -f $VariableValue,$VariableName)

        } else {
            New-Item -ItemType Directory -Path $VariableValue
        }
    }
}

function Assert-Variable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VariableName
    )

    if (-Not (Get-Variable -Name $VariableName -ValueOnly -ErrorAction SilentlyContinue)) {
        throw ('Variable <{0}> is not defined. Aborting.' -f $VariableName)
    }
}

function Assert-PsDscBasePath {
    [CmdletBinding()]
    param()
    
    Assert-PathVariable -VariableName Script:PsDscBasePath
}