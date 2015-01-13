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

function Assert-BasePath {
    [CmdletBinding()]
    param()

    Assert-PathVariable -VariableName PSDSC_BasePath
}