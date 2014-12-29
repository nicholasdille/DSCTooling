$FunctionsFile       = Join-Path -Path $PSScriptRoot -ChildPath 'Functions.ps1'
$SecureStringFile    = Join-Path -Path $PSScriptRoot -ChildPath 'Temp\SecureString.clixml'
$EncryptedStringFile = Join-Path -Path $PSScriptRoot -ChildPath 'Temp\EncryptedString.clixml'

. $FunctionsFile

#Read-Host -AsSecureString | Export-Clixml -Path $SecureStringFile
$Key = 'asdf1234hjkl5678'
Import-Clixml -Path $SecureStringFile | ConvertTo-EncryptedString -Key $Key | Export-Clixml -Path $EncryptedStringFile
Import-Clixml -Path $EncryptedStringFile | ConvertFrom-EncryptedString -Key $Key