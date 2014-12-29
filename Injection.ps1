<#
Prerequisites
- Certificate of root CA
- PFX with certificate for host
- Credentials for PFX
- Decryption key for password
- Meta configuration named localhost.meta.mof
#>

Import-Certificate -FilePath c:\dsc\demo-CA.cer -CertStoreLocation Cert:\LocalMachine\Root
Import-PfxCertificate -FilePath c:\dsc\contoso-dc-01.pfx -CertStoreLocation Cert:\LocalMachine\My -Password (Read-Host -AsSecureString)
Ren c:\dsc\9565b711-30c2-43d5-a929-2167955733d3.meta.mof c:\dsc\localhost.meta.mof
Set-DscLocalConfigurationManager -Path c:\dsc