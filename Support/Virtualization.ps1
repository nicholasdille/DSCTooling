function Get-VmIdFromHyperV {
    [CmdletBinding()]
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$VMMServer
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    (Get-SCVirtualMachine @PSBoundParameters | Select Id).Id
}

function Get-VmIp {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ComputerName
        ,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VmName
        ,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $IPv4Pattern = '^\d+\.\d+\.\d+\.\d+$'
    )

    (Get-VM -ComputerName $ComputerName -Name $VmName).NetworkAdapters[0].IPAddresses | Where-Object { $_ -match $IPv4Pattern } | Select-Object -First 1
}