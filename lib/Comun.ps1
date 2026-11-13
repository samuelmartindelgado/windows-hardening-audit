# Funciones auxiliares comunes. Todo es de solo lectura.

function Get-RegValue {
    <#
    .SYNOPSIS
        Lee un valor del registro. Devuelve $null si la clave o el valor no existen.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function New-Resultado {
    <#
    .SYNOPSIS
        Crea el objeto de resultado estándar de una comprobación.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Categoria,
        [Parameter(Mandatory)][string]$Nombre,
        [Parameter(Mandatory)][ValidateSet('OK', 'AVISO', 'FALLO', 'NO_COMPROBADO')][string]$Estado,
        [Parameter(Mandatory)][ValidateSet('Alta', 'Media', 'Baja')][string]$Severidad,
        [string]$Detalle = '',
        [string]$Recomendacion = '',
        [string]$Referencia = ''
    )
    [pscustomobject]@{
        Id            = $Id
        Categoria     = $Categoria
        Nombre        = $Nombre
        Estado        = $Estado
        Severidad     = $Severidad
        Detalle       = $Detalle
        Recomendacion = $Recomendacion
        Referencia    = $Referencia
    }
}

function Test-EsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-EsServidor {
    try {
        return ((Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType -ne 1)
    }
    catch {
        return $false
    }
}

function Get-MensajeCorto {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $m = $ErrorRecord.Exception.Message -replace '\s+', ' '
    if ($m.Length -gt 160) { $m = $m.Substring(0, 157) + '...' }
    return $m
}
