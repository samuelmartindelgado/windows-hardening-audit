@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Write-Host se usa a propósito para la salida en colores de la consola
        'PSAvoidUsingWriteHost',
        # Las funciones Test-* devuelven un objeto; no son cmdlets que cambien estado
        'PSUseShouldProcessForStateChangingFunctions',
        # Nombres en español en plural (Test-Actualizaciones, Test-AdminsLocales) a propósito
        'PSUseSingularNouns'
    )
}
