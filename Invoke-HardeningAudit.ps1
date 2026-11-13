<#
.SYNOPSIS
    Audita la configuración de seguridad de un equipo Windows y genera un informe HTML y JSON.

.DESCRIPTION
    Ejecuta 23 comprobaciones de hardening (red, cuentas, credenciales y sistema) basadas en CIS y en las
    recomendaciones de Microsoft. Es de SOLO LECTURA: no cambia ninguna configuración.
    Funciona sin administrador; las comprobaciones que lo necesitan aparecen como NO_COMPROBADO.

.PARAMETER OutputPath
    Carpeta donde se guardan los informes. Por defecto, la carpeta actual.

.PARAMETER Format
    Html, Json o ambos. Por defecto, ambos.

.PARAMETER FailOnFallo
    Termina con código 1 si hay algún FALLO de severidad Alta. Útil en integración continua.

.PARAMETER Quiet
    No muestra la tabla de resultados en la consola.

.EXAMPLE
    .\Invoke-HardeningAudit.ps1
    Audita el equipo y deja el informe HTML y JSON en la carpeta actual.

.EXAMPLE
    .\Invoke-HardeningAudit.ps1 -OutputPath C:\Informes -Format Html
    Solo el informe HTML, en C:\Informes.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [ValidateSet('Html', 'Json')][string[]]$Format = @('Html', 'Json'),
    [switch]$FailOnFallo,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$raiz = $PSScriptRoot
. (Join-Path $raiz 'lib\Comun.ps1')
. (Join-Path $raiz 'lib\Informe.ps1')
Get-ChildItem -Path (Join-Path $raiz 'checks') -Filter '*.ps1' | Sort-Object Name | ForEach-Object { . $_.FullName }

# Ejecuta todas las funciones Test-* definidas en checks/
$funciones = Get-ChildItem -Path (Join-Path $raiz 'checks') -Filter '*.ps1' | ForEach-Object {
    [regex]::Matches((Get-Content $_.FullName -Raw), '(?m)^function\s+(Test-[\w-]+)') | ForEach-Object { $_.Groups[1].Value }
}
$resultados = @(foreach ($f in $funciones) {
        try { & $f }
        catch { New-Resultado -Id $f -Categoria 'Error' -Nombre $f -Estado NO_COMPROBADO -Severidad Baja -Detalle (Get-MensajeCorto $_) }
    }) | Sort-Object Id

$so = 'Desconocido'
try { $so = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { $so = 'Desconocido' }
$tipo = 'PC'
if (Test-EsServidor) { $tipo = 'Servidor' }
$admin = 'No'
if (Test-EsAdmin) { $admin = 'Sí' }
$meta = [pscustomobject]@{
    Equipo     = $env:COMPUTERNAME
    Sistema    = $so
    Tipo       = $tipo
    Admin      = $admin
    Fecha      = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    Puntuacion = (Get-Puntuacion $resultados)
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }
$base = Join-Path $OutputPath ("hardening_{0}_{1}" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmm'))
$utf8 = New-Object System.Text.UTF8Encoding($false)
if ($Format -contains 'Html') {
    [System.IO.File]::WriteAllText("$base.html", (New-InformeHtml -Meta $meta -Resultados $resultados), $utf8)
}
if ($Format -contains 'Json') {
    $json = [pscustomobject]@{ Meta = $meta; Resultados = $resultados } | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText("$base.json", $json, $utf8)
}

if (-not $Quiet) {
    $colores = @{ OK = 'Green'; AVISO = 'Yellow'; FALLO = 'Red'; NO_COMPROBADO = 'DarkGray' }
    Write-Host ''
    Write-Host ("Auditoría de {0} ({1}) - puntuación {2}%" -f $meta.Equipo, $meta.Tipo, $meta.Puntuacion)
    foreach ($r in $resultados) {
        Write-Host ("{0,-7} " -f $r.Id) -NoNewline
        Write-Host ("{0,-14}" -f $r.Estado) -ForegroundColor $colores[$r.Estado] -NoNewline
        Write-Host $r.Nombre
    }
    $c = $resultados | Group-Object Estado | ForEach-Object { "$($_.Name): $($_.Count)" }
    Write-Host ''
    Write-Host ($c -join ' · ')
    Write-Host "Informe: $base.*"
}

if ($FailOnFallo -and @($resultados | Where-Object { $_.Estado -eq 'FALLO' -and $_.Severidad -eq 'Alta' }).Count -gt 0) {
    exit 1
}
exit 0
