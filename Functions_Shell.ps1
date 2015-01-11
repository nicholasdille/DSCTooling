function Assert-PathVariable {
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
            Write-Error ('Path <{0}> specified in variable <{1}> does not exist. Aborting.' -f $VariableValue,$VariableName)
            throw

        } else {
            New-Item -ItemType Directory -Path $VariableValue
        }
    }
}

function Assert-Variable {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $VariableName
    )

    if (-Not (Get-Variable -Name $VariableName -ValueOnly -ErrorAction SilentlyContinue)) {
        Write-Error ('Variable <{0}> is not defined. Aborting.' -f $VariableName)
        throw
    }
}

function Assert-BasePath {
    Assert-PathVariable -VariableName PSDSC_BasePath
}