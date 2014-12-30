Function New-Password() {
    Param(
        [int]$Length=10
        ,
        [string[]]$Alphabet
    )

    if (-Not $Alphabet) {
        $Alphabet = $null
        40..126 + 33 + 35..38 | foreach {
            $Alphabet += ,[char][byte]$_
        }
    }

    For ($i = 1; $i –le $Length; $i++) {
        $TempPassword += ($Alphabet | Get-Random)
    }

    return $TempPassword
}