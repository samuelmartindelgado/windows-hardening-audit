# Genera el informe HTML (autocontenido, sin JavaScript) y el JSON.

function ConvertTo-Html5Seguro {
    param([AllowNull()][string]$Texto)
    if ($null -eq $Texto) { return '' }
    [System.Net.WebUtility]::HtmlEncode($Texto)
}

function Get-Puntuacion {
    param([object[]]$Resultados)
    $evaluados = @($Resultados | Where-Object { $_.Estado -ne 'NO_COMPROBADO' })
    if ($evaluados.Count -eq 0) { return 0 }
    $ok = @($evaluados | Where-Object { $_.Estado -eq 'OK' }).Count
    [int][math]::Round(100 * $ok / $evaluados.Count)
}

function New-InformeHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Meta,
        [Parameter(Mandatory)][object[]]$Resultados
    )
    $e = { param($t) ConvertTo-Html5Seguro $t }
    $cuenta = @{}
    foreach ($s in 'OK', 'AVISO', 'FALLO', 'NO_COMPROBADO') { $cuenta[$s] = @($Resultados | Where-Object { $_.Estado -eq $s }).Count }
    $punt = Get-Puntuacion $Resultados
    $colorPunt = '#16a34a'
    if ($punt -lt 80) { $colorPunt = '#d97706' }
    if ($punt -lt 50) { $colorPunt = '#dc2626' }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append(@"
<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoría de hardening - $(& $e $Meta.Equipo)</title>
<style>
:root{--bg:#f8fafc;--card:#fff;--txt:#0f172a;--sub:#64748b;--borde:#e2e8f0}
@media (prefers-color-scheme: dark){:root{--bg:#0f172a;--card:#1e293b;--txt:#f1f5f9;--sub:#94a3b8;--borde:#334155}}
body{margin:0;padding:24px;background:var(--bg);color:var(--txt);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto}
h1{margin:0 0 4px;font-size:26px} .sub{color:var(--sub)}
.cab{display:flex;flex-wrap:wrap;gap:16px;align-items:center;justify-content:space-between;margin-bottom:20px}
.punt{font-size:56px;font-weight:700;color:$colorPunt;line-height:1}
.chips{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 24px}
.chip{padding:8px 14px;border-radius:999px;font-weight:600;color:#fff}
.OK{background:#16a34a}.AVISO{background:#d97706}.FALLO{background:#dc2626}.NO_COMPROBADO{background:#64748b}
h2{margin:28px 0 8px;font-size:18px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--borde);border-radius:10px;overflow:hidden}
table{table-layout:fixed} th:nth-child(1){width:80px} th:nth-child(2){width:140px} th:nth-child(4){width:90px}
th,td{padding:10px 12px;border-bottom:1px solid var(--borde);text-align:left;vertical-align:top}
th{font-size:13px;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
.est{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-size:12px;font-weight:700;white-space:nowrap}
.rec{color:var(--sub);font-size:13px;margin-top:4px} .id{font-family:Consolas,monospace;color:var(--sub);white-space:nowrap}
footer{margin-top:28px;color:var(--sub);font-size:13px}
</style></head><body><div class="wrap">
<div class="cab"><div><h1>Auditoría de hardening de Windows</h1>
<div class="sub">$(& $e $Meta.Equipo) · $(& $e $Meta.Sistema) · $(& $e $Meta.Tipo) · $(& $e $Meta.Fecha) · Administrador: $(& $e $Meta.Admin)</div></div>
<div style="text-align:right"><div class="punt">$punt%</div><div class="sub">comprobaciones correctas</div></div></div>
<div class="chips">
<span class="chip OK">OK: $($cuenta.OK)</span><span class="chip AVISO">Aviso: $($cuenta.AVISO)</span>
<span class="chip FALLO">Fallo: $($cuenta.FALLO)</span><span class="chip NO_COMPROBADO">No comprobado: $($cuenta.NO_COMPROBADO)</span>
</div>
"@)
    foreach ($grupo in ($Resultados | Group-Object Categoria)) {
        [void]$sb.Append("<h2>$(& $e $grupo.Name)</h2><table><tr><th>Id</th><th>Estado</th><th>Comprobación</th><th>Severidad</th></tr>")
        foreach ($r in $grupo.Group) {
            $rec = ''
            if ($r.Recomendacion -and $r.Estado -ne 'OK') { $rec = "<div class=""rec"">&#8594; $(& $e $r.Recomendacion)</div>" }
            [void]$sb.Append("<tr><td class=""id"">$(& $e $r.Id)</td><td><span class=""est $($r.Estado)"">$(& $e ($r.Estado -replace '_',' '))</span></td>" +
                "<td><strong>$(& $e $r.Nombre)</strong><div>$(& $e $r.Detalle)</div>$rec</td><td>$(& $e $r.Severidad)</td></tr>")
        }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append("<footer>Generado por windows-hardening-audit. Solo lectura: esta herramienta no cambia nada en el equipo.</footer></div></body></html>")
    $sb.ToString()
}
