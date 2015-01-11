function Assert-OutputPath {
    Assert-PathVariable -VariableName PSDSC_OutputPath
}

function Clear-OutputPath {
    Assert-OutputPath
    Get-ChildItem "$PSDSC_OutputPath" | foreach {
        Remove-Item -Path "$($_.FullName)" -Force
    }
}

function Assert-DscCheckSum {
    Assert-OutputPath
    New-DscCheckSum -ConfigurationPath $PSDSC_OutputPath
}

function Invoke-DscConfig {
    Assert-BasePath

    . $PSDSC_DataFile
    Import-Module $PSDSC_ConfigFile

    Assert-OutputPath
    Clear-OutputPath

    LabConfiguration -OutputPath $PSDSC_OutputPath -ConfigurationData $ConfigData

    Assert-DscCheckSum
    Publish-DscConfig
}