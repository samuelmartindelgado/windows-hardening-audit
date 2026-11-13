# Comprobaciones de cuentas locales. Solo lectura.

function Test-AdminIntegrado {
    $p = @{ Id = 'CTA-01'; Categoria = 'Cuentas'; Nombre = 'Administrador integrado deshabilitado o renombrado'; Severidad = 'Media'
        Referencia = 'CIS 2.3.1.1 / 2.3.1.5' }
    try {
        $u = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-500' } | Select-Object -First 1
        if (-not $u) { return New-Resultado @p -Estado NO_COMPROBADO -Detalle 'No se encontró la cuenta -500.' }
        if (-not $u.Enabled) { return New-Resultado @p -Estado OK -Detalle "La cuenta '$($u.Name)' está deshabilitada." }
        if ($u.Name -in @('Administrator', 'Administrador')) {
            return New-Resultado @p -Estado AVISO -Detalle "La cuenta '$($u.Name)' está habilitada y con su nombre por defecto." `
                -Recomendacion 'Deshabilítala y usa cuentas personales con privilegios, o al menos renómbrala y gestiona su contraseña con LAPS.'
        }
        New-Resultado @p -Estado OK -Detalle "Habilitada pero renombrada a '$($u.Name)'."
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle ('No hay cuentas locales consultables (¿controlador de dominio?): ' + (Get-MensajeCorto $_))
    }
}

function Test-Invitado {
    $p = @{ Id = 'CTA-02'; Categoria = 'Cuentas'; Nombre = 'Cuenta de invitado deshabilitada'; Severidad = 'Media'
        Referencia = 'CIS 2.3.1.2' }
    try {
        $u = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1
        if (-not $u -or -not $u.Enabled) { return New-Resultado @p -Estado OK -Detalle 'La cuenta de invitado está deshabilitada.' }
        New-Resultado @p -Estado FALLO -Detalle "La cuenta '$($u.Name)' está habilitada." -Recomendacion 'Deshabilita la cuenta de invitado.'
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}

function Test-AdminsLocales {
    $p = @{ Id = 'CTA-03'; Categoria = 'Cuentas'; Nombre = 'Miembros del grupo Administradores'; Severidad = 'Media'
        Referencia = 'Principio de mínimo privilegio' }
    try {
        $miembros = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { $_.Name })
        $lista = $miembros -join ', '
        if ($miembros.Count -gt 3) {
            return New-Resultado @p -Estado AVISO -Detalle "$($miembros.Count) miembros: $lista" `
                -Recomendacion 'Revisa quién necesita de verdad ser administrador. Usa grupos de dominio y GPO de grupos restringidos.'
        }
        New-Resultado @p -Estado OK -Detalle "$($miembros.Count) miembros: $lista"
    }
    catch {
        # Get-LocalGroupMember falla si hay miembros huérfanos (SID de cuentas borradas)
        New-Resultado @p -Estado NO_COMPROBADO -Detalle ('No se pudo listar el grupo (puede haber miembros huérfanos): ' + (Get-MensajeCorto $_))
    }
}

function Test-Laps {
    $p = @{ Id = 'CTA-04'; Categoria = 'Cuentas'; Nombre = 'LAPS configurado'; Severidad = 'Media'
        Referencia = 'Microsoft: Windows LAPS overview' }
    $nueva = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS')
    $antigua = (Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -Name 'AdmPwdEnabled') -eq 1
    if ($nueva) { return New-Resultado @p -Estado OK -Detalle 'Directiva de Windows LAPS presente.' }
    if ($antigua) { return New-Resultado @p -Estado OK -Detalle 'LAPS heredado (AdmPwd) activado.' }
    $enDominio = $false
    try { $enDominio = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { $enDominio = $false }
    $nota = 'Equipo fuera de dominio: LAPS solo aplica en dominio o Entra ID.'
    if ($enDominio) { $nota = 'Equipo en dominio sin LAPS: la contraseña del administrador local probablemente se repite entre equipos.' }
    New-Resultado @p -Estado AVISO -Detalle $nota -Recomendacion 'Despliega Windows LAPS (integrado desde abril de 2023) con una GPO.'
}
