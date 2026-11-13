#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5' }

BeforeAll {
    $raiz = Split-Path -Parent $PSScriptRoot
    . (Join-Path $raiz 'lib\Comun.ps1')
    . (Join-Path $raiz 'lib\Informe.ps1')
    Get-ChildItem (Join-Path $raiz 'checks') -Filter *.ps1 | ForEach-Object { . $_.FullName }
    $script:funciones = Get-ChildItem (Join-Path $raiz 'checks') -Filter *.ps1 | ForEach-Object {
        [regex]::Matches((Get-Content $_.FullName -Raw), '(?m)^function\s+(Test-[\w-]+)') | ForEach-Object { $_.Groups[1].Value }
    }
    $script:props = 'Id', 'Categoria', 'Nombre', 'Estado', 'Severidad', 'Detalle', 'Recomendacion', 'Referencia'
}

Describe 'Comprobaciones' {
    It 'hay 23 comprobaciones' {
        $script:funciones.Count | Should -Be 23
    }

    It '<_> devuelve un resultado válido sin lanzar excepciones' -ForEach @(
        Get-ChildItem (Join-Path (Split-Path -Parent $PSScriptRoot) 'checks') -Filter *.ps1 | ForEach-Object {
            [regex]::Matches((Get-Content $_.FullName -Raw), '(?m)^function\s+(Test-[\w-]+)') | ForEach-Object { $_.Groups[1].Value }
        }
    ) {
        $r = & $_
        @($r).Count | Should -Be 1
        foreach ($p in $script:props) { $r.PSObject.Properties.Name | Should -Contain $p }
        $r.Estado | Should -BeIn @('OK', 'AVISO', 'FALLO', 'NO_COMPROBADO')
        $r.Severidad | Should -BeIn @('Alta', 'Media', 'Baja')
    }

    It 'los Id no se repiten' {
        $ids = $script:funciones | ForEach-Object { (& $_).Id }
        ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
    }
}

Describe 'Lógica con el registro simulado' {
    It 'WDigest con UseLogonCredential = 1 es FALLO' {
        Mock Get-RegValue { 1 } -ParameterFilter { $Name -eq 'UseLogonCredential' }
        (Test-WDigest).Estado | Should -Be 'FALLO'
    }
    It 'WDigest sin el valor es OK' {
        Mock Get-RegValue { $null } -ParameterFilter { $Name -eq 'UseLogonCredential' }
        (Test-WDigest).Estado | Should -Be 'OK'
    }
    It 'UAC desactivado (EnableLUA = 0) es FALLO' {
        Mock Get-RegValue { 0 } -ParameterFilter { $Name -eq 'EnableLUA' }
        (Test-Uac).Estado | Should -Be 'FALLO'
    }
    It 'RDP activado sin NLA es FALLO' {
        Mock Get-RegValue { 0 } -ParameterFilter { $Name -eq 'fDenyTSConnections' }
        Mock Get-RegValue { 0 } -ParameterFilter { $Name -eq 'UserAuthentication' }
        (Test-Rdp).Estado | Should -Be 'FALLO'
    }
    It 'RDP desactivado es OK' {
        Mock Get-RegValue { 1 } -ParameterFilter { $Name -eq 'fDenyTSConnections' }
        (Test-Rdp).Estado | Should -Be 'OK'
    }
    It 'LmCompatibilityLevel 1 es FALLO y 5 es OK' {
        Mock Get-RegValue { 1 } -ParameterFilter { $Name -eq 'LmCompatibilityLevel' }
        (Test-LmCompat).Estado | Should -Be 'FALLO'
        Mock Get-RegValue { 5 } -ParameterFilter { $Name -eq 'LmCompatibilityLevel' }
        (Test-LmCompat).Estado | Should -Be 'OK'
    }
    It 'LLMNR sin directiva es FALLO' {
        Mock Get-RegValue { $null } -ParameterFilter { $Name -eq 'EnableMulticast' }
        (Test-Llmnr).Estado | Should -Be 'FALLO'
    }
}

Describe 'Informe' {
    BeforeAll {
        $script:meta = [pscustomobject]@{ Equipo = 'EQUIPO-PRUEBA'; Sistema = 'Windows'; Tipo = 'PC'; Admin = 'No'; Fecha = '2026-01-01 10:00'; Puntuacion = 50 }
        $script:res = @(
            New-Resultado -Id 'X-01' -Categoria 'Red' -Nombre 'Uno' -Estado OK -Severidad Alta
            New-Resultado -Id 'X-02' -Categoria 'Red' -Nombre '<script>alert(1)</script>' -Estado FALLO -Severidad Alta -Recomendacion 'Arreglar'
        )
    }
    It 'contiene el nombre del equipo' {
        New-InformeHtml -Meta $script:meta -Resultados $script:res | Should -Match 'EQUIPO-PRUEBA'
    }
    It 'codifica el HTML y no deja etiquetas <script>' {
        New-InformeHtml -Meta $script:meta -Resultados $script:res | Should -Not -Match '<script'
    }
    It 'la puntuación ignora NO_COMPROBADO' {
        $r = @(
            New-Resultado -Id 'A' -Categoria 'C' -Nombre 'a' -Estado OK -Severidad Baja
            New-Resultado -Id 'B' -Categoria 'C' -Nombre 'b' -Estado NO_COMPROBADO -Severidad Baja
        )
        Get-Puntuacion $r | Should -Be 100
    }
}

Describe 'Script principal' {
    It 'genera un JSON válido con 23 resultados' {
        $raiz = Split-Path -Parent $PSScriptRoot
        $salida = Join-Path ([IO.Path]::GetTempPath()) ('hardening_test_' + [guid]::NewGuid())
        & (Join-Path $raiz 'Invoke-HardeningAudit.ps1') -OutputPath $salida -Format Json -Quiet
        $f = Get-ChildItem $salida -Filter *.json | Select-Object -First 1
        $j = Get-Content $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        $j.Resultados.Count | Should -Be 23
        Remove-Item $salida -Recurse -Force
    }
}

Describe 'Solo lectura' {
    It 'ningún fichero usa cmdlets que cambien la configuración' {
        $raiz = Split-Path -Parent $PSScriptRoot
        $prohibidos = 'Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Service', 'Stop-Service',
        'Set-SmbServerConfiguration', 'Enable-WindowsOptionalFeature', 'Disable-WindowsOptionalFeature', 'Set-NetFirewallProfile', 'reg add'
        $codigo = Get-ChildItem (Join-Path $raiz 'checks'), (Join-Path $raiz 'lib') -Filter *.ps1 |
            ForEach-Object { Get-Content $_.FullName -Raw } |
            ForEach-Object { ($_ -split "`n" | Where-Object { $_ -notmatch "^\s*#" -and $_ -notmatch "Recomendacion|\`$rec\s*=" }) -join "`n" }
        foreach ($p in $prohibidos) { ($codigo -join "`n") | Should -Not -Match ([regex]::Escape($p)) }
    }
}
