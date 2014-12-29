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