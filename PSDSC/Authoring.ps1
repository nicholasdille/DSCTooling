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

function New-DscResourceArchive {
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
    )

    $DscModulePath = 'C:\Program Files\WindowsPowerShell\Modules'
    $ModuleVersion = Get-Module -ListAvailable | Where-Object Name -ieq $ModuleName | Select-Object -ExpandProperty Version
    $ModulePath = Get-ChildItem $DscModulePath | Where-Object Name -ieq $ModuleName

    $ArchivePath = Join-Path -Path $Path -ChildPath ('{0}_{1}.zip' -f $ModuleName, $ModuleVersion)

    Compress-Archive -DestinationPath $ArchivePath -Path $ModulePath.FullName -CompressionLevel Optimal
}