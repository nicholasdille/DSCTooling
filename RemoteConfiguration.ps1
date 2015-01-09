$VmHost = 'hv-04.demo.dille.name'
$VmName = 'contoso-sql-01'
$Guid = '1ca1728d-f336-4772-bfa1-90b4758fc7f9'
$IPv4Pattern = '^\d+\.\d+\.\d+\.\d+$'
$LocalBasePath = 'c:\dsc'

$LocalCredFile  = Join-Path -Path $PSScriptRoot -ChildPath 'Cred\administrator@WIN-xxxxxxxx.clixml'
$DomainCredFile = Join-Path -Path $PSScriptRoot -ChildPath 'Cred\administrator@demo.dille.name.clixml'
$CertCredFile   = Join-Path -Path $PSScriptRoot -ChildPath 'Cred\Certificates.clixml'
$CaFile         = Join-Path -Path $PSScriptRoot -ChildPath 'Cert\demo-CA.cer'
$CertFile       = Join-Path -Path $PSScriptRoot -ChildPath 'Cert\contoso-sql-01.pfx'
$MetaFile       = Join-Path -Path $PSScriptRoot -ChildPath "Output\$Guid.meta.mof"

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
