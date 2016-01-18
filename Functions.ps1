function Build-DscNodeArray {
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
    [OutputType([System.Array])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = $PSScriptRoot
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Filter
    )

    $NodePath = (Join-Path -Path $PSScriptRoot -ChildPath 'Node')
    $CertPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Cert')

    Write-Verbose ('[{0}] Collecting nodes from directory <{1}>' -f $MyInvocation.MyCommand, $NodePath)

    $AllNodes = @()
    Get-ChildItem -Recurse $NodePath | Where-Object Name -like '*.ps1' | ForEach-Object {
        Write-Verbose ('[{0}] Processing file <{1}>' -f $MyInvocation.MyCommand, $_.Name)

        if (-Not $Filter -Or $Filter -icontains $_.BaseName) {
            $Node = $(. $_.FullName)
            Write-Verbose ('[{0}] Processing node {1} with computername {2}' -f $MyInvocation.MyCommand, $Node.NodeName, $Node.Roles.Computer.MachineName)

            $CertFile = Join-Path -Path $CertPath -ChildPath "$($Node.NodeName).cer"
            Write-Verbose ('[{0}] Using certificate file <{1}>' -f $MyInvocation.MyCommand, $CertFile)

            if (Test-Path -Path $CertFile) {
                Write-Verbose ('[{0}] Adding certificate file to node configuration' -f $MyInvocation.MyCommand)
                $Node.Add('CertificateFile', $CertFile)

                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                $Certificate.Import($Node.CertificateFile)
                Write-Verbose ('[{0}] Adding certificate thumbprint <{1}> to node configuration' -f $MyInvocation.MyCommand, $Certificate.Thumbprint)
                $Node.Add('CertificateThumbprint', $Certificate.Thumbprint)

                Write-Verbose ('[{0}] Adding node configuration to result array' -f $MyInvocation.MyCommand)
                $AllNodes = $AllNodes + $Node

            } else {
                Write-Error ('[{0}] Unable to find certificate file {1}. Skipping node {2}' -f $MyInvocation.MyCommand, $CertFile, $Node.Roles.Computer.MachineName)
            }
        }
    }

    Write-Verbose ('[{0}] Done. Returning node configurations' -f $MyInvocation.MyCommand)
    $AllNodes
}

function Build-DscCredentialsArray {
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
        $Path = $PSScriptRoot
    )

    $CredPath = (Join-Path -Path $Path -ChildPath 'Cred')

    Write-Verbose ('[{0}] Collecting credentials from directory {1}' -f $MyInvocation.MyCommand, $CredPath)

    $Credentials = @{}
    Get-ChildItem -Recurse $CredPath | Where-Object Name -like '*.clixml' | ForEach-Object {
        Write-Verbose ('[{0}] Processing credential <{1}>' -f $MyInvocation.MyCommand, $_.BaseName)

        Write-Verbose ('[{0}] Adding credential <{1}> to with file <{2}>' -f $MyInvocation.MyCommand, $_.BaseName, $_.FullName)
        $Credentials.Add($_.BaseName, $_.FullName)
    }

    Write-Verbose ('[{0}] Done and returning credentials' -f $MyInvocation.MyCommand)
    $Credentials
}

function Build-DscConfig {
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
        $Path = $PSScriptRoot
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Filter
    )

    $CertPath = (Join-Path -Path $Path -ChildPath 'Cert')
    $CredPath = (Join-Path -Path $Path -ChildPath 'Cred')
    $NodePath = (Join-Path -Path $Path -ChildPath 'Node')

    Write-Verbose ('[{0}] Building configuration data' -f $MyInvocation.MyCommand)

    $ConfigData = @{
        AllNodes = @()
        Credentials = @{}
        Environment = @{}
    }

    Write-Verbose ('[{0}] Adding environment configuration to configuration data' -f $MyInvocation.MyCommand)
    $ConfigData['Environment'] = $(. (Join-Path -Path $Path -ChildPath 'EnvironmentConfiguration.ps1'))

    Write-Verbose ('[{0}] Adding credentials to configuration data' -f $MyInvocation.MyCommand)
    $ConfigData['Credentials'] = Build-DscCredentialsArray -Path $Path

    Write-Verbose ('[{0}] Adding nodes to configuration data' -f $MyInvocation.MyCommand)
    $params = @{
        Path = $Path
    }
    if ($Filter) {$params.Add('Filter', $Filter)}
    $ConfigData['AllNodes'] = @(Build-DscNodeArray @params)

    Write-Verbose ('[{0}] Done and returning configuration data' -f $MyInvocation.MyCommand)
    $ConfigData
}

function Invoke-DscConfig {
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
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = $PSScriptRoot
        ,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Filter
    )

    $CertPath   = (Join-Path -Path $Path -ChildPath 'Cert')
    $CredPath   = (Join-Path -Path $Path -ChildPath 'Cred')
    $NodePath   = (Join-Path -Path $Path -ChildPath 'Node')
    $OutputPath = (Join-Path -Path $Path -ChildPath 'Output')

    Write-Verbose ('[{0}] Using the folloing input parameters: CertPath={1} CredPath={2} NodePath={3} OutputPath={4} Filter={5}' -f $MyInvocation.MyCommand, $CertPath, $CredPath, $NodePath, $OutputPath, ($Filter -join ';'))

    Write-Verbose ('[{0}] Building configuration data' -f $MyInvocation.MyCommand)
    $params = @{
        Path = $Path
    }
    if ($Filter) {$params.Add('Filter', $Filter)}
    $ConfigData = Build-DscConfig @params

    Write-Verbose ('[{0}] Importing node configuration' -f $MyInvocation.MyCommand)
    Import-Module (Join-Path -Path $Path -ChildPath 'Configuration.psm1') -Force

    Write-Verbose ('[{0}] Invoking node configuration' -f $MyInvocation.MyCommand)
    MasterConfiguration -OutputPath $OutputPath -ConfigurationData $ConfigData

    Write-Verbose ('[{0}] Done')
}