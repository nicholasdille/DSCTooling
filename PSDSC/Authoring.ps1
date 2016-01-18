function New-DscNode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $WebenrollServer
    )

    #region variables
    $GUID = [System.Guid]::NewGuid().Guid
    $WebEnrollURL = "https://$WebenrollServer/ADPolicyProvider_CEP_UsernamePassword/service.svc/CEP"
    $WebEnrollCred = Get-Credential -Message 'Enter Credentials valid for certificate requests'
    $Template = 'DSCEncryption'
    $PFXPath = 'C:\PFXSite'
    $CERPath = 'C:\PublicCerts'
    $PFXPwd = ([char[]](Get-Random -Input $(48..57 + 65..90 + 97..122) -Count 12)) -join ''
    $SecPFXPwd = $PFXPwd | ConvertTo-SecureString -AsPlainText -Force
    #endregion variables
 
    #region logic
    try {
        Write-Verbose -Message "Requesting certificate from template: $Template at URI: $WebEnrollURL" -Verbose
        $cert = Get-Certificate -Url $WebEnrollURL -Template $Template -SubjectName "CN=$GUID" -CertStoreLocation Cert:\LocalMachine\My -Credential $WebEnrollCred -ErrorAction Stop
        Write-Verbose -Message 'Succesfully requested certificate'

    } catch {
        throw 'Certificate Request failed'
    }

    Write-Verbose -Message "Exporting certificate with Private and Public Key to PFX at path: $PFXPath" -Verbose
    Export-PfxCertificate -Cert $cert.Certificate.PSPath -Password $SecPFXPwd -FilePath "$PFXPath\$($cert.Certificate.Subject.TrimStart('CN=')).pfx" -ChainOption EndEntityCertOnly -Force | Out-Null
    $PFXPwd | Out-File -FilePath "$PFXPath\$($cert.Certificate.Subject.TrimStart('CN=')).txt"
 
    Write-Verbose -Message "Exporting Certificate with Public key to cer file at path: $CERPath" -Verbose
    Export-Certificate -Cert $cert.Certificate.PSPath -FilePath "$CERPath\$($cert.Certificate.Subject.TrimStart('CN=')).cer" -Type CERT -Force | Out-Null
 
    Write-Verbose -Message 'Removing certificate from computer store' -Verbose
    Remove-Item $cert.Certificate.PSPath -Force
    #endregion logic
 
    #region output
    $Props = @{
        GUID = $GUID
        PWD = $PFXPwd
        PFX = "$PFXPath\$($cert.Certificate.Subject.TrimStart('CN=')).pfx"
        CER = "$CERPath\$($cert.Certificate.Subject.TrimStart('CN=')).cer"
    }
    New-Object -TypeName PSObject -Property $Props | Format-List
    #endregion output
}

function Find-DscResourceInUse {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    Get-Content (Join-Path -Path $PSScriptRoot -ChildPath 'Configuration.psm1') | foreach {
        if ($_ -imatch 'import-dscresource( -module(name)?)? ([^\s]+)') {
            $ModuleName = $Matches[3]
            $SourcePath = Join-Path -Path 'C:\Program Files\WindowsPowerShell\Modules' -ChildPath $ModuleName

            Copy-Item -Path $SourcePath -Destination .\$ModuleName -Recurse -Force
        }
    }
}

function Publish-DscResourceArchiveToPullServer {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>

    #
}

function New-DscResourceArchive {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER ModuleName
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    New-DscResourceArchive -ModuleName xActiveDirectory -Path .

    .NOTES
    XXX
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ModuleName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ModulePath = 'C:\Program Files\WindowsPowerShell\Modules'
    )

    Write-Verbose ('[{0}] Archiving module {1} to path {2} (from module path {2}' -f $MyInvocation.MyCommand, $ModuleName, $Path, $ModulePath)

    $DscModuleVersion = Get-Module -ListAvailable | Where-Object Name -ieq $ModuleName | Select-Object -ExpandProperty Version
    Write-Verbose ('[{0}] Found module version {1}' -f $MyInvocation.MyCommand, $DscModuleVersion)

    $DscModulePath = Get-ChildItem $ModulePath | Where-Object Name -ieq $ModuleName
    Write-Verbose ('[{0}] Full path to module is {1}' -f $MyInvocation.MyCommand, $DscModulePath)

    $FileName = '{0}_{1}.zip' -f $ModuleName, $DscModuleVersion
    Write-Verbose ('[{0}] Archive name is {1}' -f $MyInvocation.MyCommand, $FileName)

    $ArchivePath = Join-Path -Path $Path -ChildPath $FileName
    Write-Verbose ('[{0}] Full path to archive is {1}' -f $MyInvocation.MyCommand, $ArchivePath)

    Compress-Archive -DestinationPath $ArchivePath -Path $DscModulePath.FullName -CompressionLevel Optimal

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Convert-DscMetaConfigurations {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path
    )

    Write-Verbose ('[{0}] Processing MOF files in {1}' -f $MyInvocation.MyCommand, $Path)
    
    Get-ChildItem -Path $Path | Where-Object { $_.Name -imatch '\.meta\.mof$' } | foreach {
        Write-Verbose ('[{0}] Processing file {1}' -f $MyInvocation.MyCommand, $_.FullName)
        Convert-DscMetaConfiguration -MofFullName $_.FullName
    }

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Convert-DscMetaConfiguration {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$MofFullName
    )

    Write-Verbose ('[{0}] Processing MOF file {1}' -f $MyInvocation.MyCommand)
    
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
    Write-Verbose ('[{0}] Writing corrected MOF to file {1}' -f $MyInvocation.MyCommand, $_.FullName)
    $MofContent | Set-Content -Path $_.FullName
}

function New-DscNodeConfig {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $NodeName = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    )

    @{
        NodeName              = $NodeName
        Roles = @{
            #
        }
        WindowsFeatures = @(
            @{ Ensure = 'Present'; Name = 'Hyper-V-PowerShell' }
        )
        Services = @(
            @{ Name = 'WMSVC'; StartupType = 'Automatic'; State = 'Running'; DependsOn = '[WindowsFeature]Web-Mgmt-Service' }
        )
        RegistrySettings = @(
            @{
                Ensure = 'Present'
                Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server'
                ValueName = 'EnableRemoteManagement'
                ValueType = 'Dword'
                ValueData = '1'
                DependsOn = ('[WindowsFeature]Web-Mgmt-Service', '[Service]WMSVC')
            }
        )
    }
}

function Push-DscConfig {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
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

    Write-Verbose ('[{0}] Pushing configuration from path {1} to computer {2}' -f $MyInvocation.MyCommand, $Path, $ComputerName)

    if ($CredentialName) {
        Write-Verbose ('[{0}] Using credentials {1}' -f $MyInvocation.MyCommand, $CredentialName)
        Start-DscConfiguration -ComputerName $ComputerName -Path $Path -Wait -Verbose -Credential (Get-CredentialFromStore -CredentialName $CredentialName)

    } else {
        Write-Verbose ('[{0}] Not using credentials' -f $MyInvocation.MyCommand)
        Start-DscConfiguration -ComputerName $ComputerName -Path $Path -Wait -Verbose
    }

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Publish-DscConfigToPullServer {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
    )

    Write-Verbose ('[{0}] Publishing node configurations from output path {1} to pull server {2}' -f $MyInvocation.MyCommand, $PSDSC_OutputPath, $ComputerName)

    $RemotePath = '\\{0}\c$\Program Files\WindowsPowershell\DscService\Configuration' -f $ComputerName
    Write-Verbose ('[{0}] Using remote path {1}' -f $MyInvocation.MyCommand, $RemotePath)

    Get-ChildItem -Path "$PSDSC_OutputPath" | Where-Object { $_.Name -imatch '^(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\.mof(\.checksum)?$' } | foreach {
        Write-Verbose ('[{0}] Publishing configuration {1}' -f $MyInvocation.MyCommand, $_.FullName)
        Copy-Item -Path "$($_.FullName)" -Destination $RemotePath -Force
    }

    Write-Verbose ('[{0}] Done' -f $MyInvocation.MyCommand)
}

function Invoke-CommandOnFile {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
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
        [string[]]
        $Files
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        #[string]
        $ScriptBlock
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
    
    Copy-VMFileRemotely -PsSession $PsSession -VmName $VmName -Files $Files -DestinationPath $LocalBasePath
    $VmIp = Get-VmIp -ComputerName $VmHost -VmName $VmName
    Invoke-Command -Session (New-PsRemoteSession -ComputerName $VmIp -CredentialName $LocalCredentialName) -ScriptBlock $ScriptBlock
}

function Set-DscMetaConfig {
    <#
    .SYNOPSIS
    XXX

    .DESCRIPTION
    XXX

    .PARAMETER Path
    XXX

    .EXAMPLE
    XXX

    .NOTES
    XXX
    #>
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
        $MetaConfig
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
    
    <#Copy-VMFileRemotely -PsSession $PsSession -VmName $VmName -Files ($MetaConfig) -DestinationPath $LocalBasePath
    $VmIp = Get-VmIp -ComputerName $VmHost -VmName $VmName
    Invoke-Command -Session (New-PsRemoteSession -ComputerName $VmIp -CredentialName $LocalCredentialName) -ScriptBlock {
        Get-ChildItem $Using:LocalBasePath\*.meta.mof | Where-Object { $_.BaseName -notmatch 'localhost.meta.mof' } | Select-Object -First 1 | Rename-Item -NewName localhost.meta.mof -ErrorAction SilentlyContinue
        Set-DscLocalConfigurationManager -Path $Using:LocalBasePath -ComputerName localhost
    }#>

    Invoke-CommandOnFile -PsSession $PsSession -VmName $VmName -LocalCredentialName $LocalCredentialName -Files ($MetaConfig) -LocalBasePath $LocalCredentialName -ScriptBlock {
        Get-ChildItem $Using:LocalBasePath\*.meta.mof | Where-Object { $_.BaseName -notmatch 'localhost.meta.mof' } | Select-Object -First 1 | Rename-Item -NewName localhost.meta.mof -ErrorAction SilentlyContinue
        Set-DscLocalConfigurationManager -Path $Using:LocalBasePath -ComputerName localhost
    }
}