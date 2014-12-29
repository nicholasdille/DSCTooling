#Requires -RunAsAdministrator

#http://technet.microsoft.com/en-us/library/dn296456.aspx

#Import-PfxCertificate -FilePath (Join-Path -Path $PSScriptRoot -ChildPath 'Lab_hv-04.pfx') -CertStoreLocation Cert:\LocalMachine\My -Password $(Get-Credential).Password

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
$NewCert = Get-ChildItem Cert:\LocalMachine\My | where { $_.Subject -icontains $NewCertCn }
$NewCertThumb = $NewCert.Thumbprint

# Export certificate to pfx
Export-PfxCertificate -Cert $NewCert -FilePath $CertPfxFile -Password (Import-Clixml -Path $CredCertFile).Password

# Extract thumbprint
(Get-PfxData -FilePath C:\Users\administrator.DEMO\OneDrive\Scripts\DSC\Cert\contoso-dc-01.pfx -Password (Import-Clixml -Path $CredCertFile).Password).EndEntityCertificates.Thumbprint | Set-Content -Path CertThumbFile
