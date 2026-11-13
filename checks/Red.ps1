# Comprobaciones de red. Solo lectura.

function Test-Smb1 {
    $p = @{ Id = 'RED-01'; Categoria = 'Red'; Nombre = 'SMBv1 desactivado en el servidor SMB'; Severidad = 'Alta'
        Referencia = 'CIS 18.4.x / Microsoft: Stop using SMB1' }
    $rec = 'Desactívalo con Set-SmbServerConfiguration -EnableSMB1Protocol $false y quita la característica SMB1Protocol.'
    try {
        $cfg = Get-SmbServerConfiguration -ErrorAction Stop
        if ($cfg.EnableSMB1Protocol) {
            return New-Resultado @p -Estado FALLO -Detalle 'EnableSMB1Protocol = True' -Recomendacion $rec
        }
        return New-Resultado @p -Estado OK -Detalle 'EnableSMB1Protocol = False'
    }
    catch {
        $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
        if ($null -eq $v) {
            return New-Resultado @p -Estado AVISO -Detalle 'No se pudo consultar la configuración SMB y el valor SMB1 no está en el registro (depende de la versión de Windows).' -Recomendacion $rec
        }
        if ($v -eq 0) { return New-Resultado @p -Estado OK -Detalle 'Registro SMB1 = 0' }
        return New-Resultado @p -Estado FALLO -Detalle "Registro SMB1 = $v" -Recomendacion $rec
    }
}

function Test-FirmaSmb {
    $p = @{ Id = 'RED-02'; Categoria = 'Red'; Nombre = 'Firma SMB obligatoria en el servidor'; Severidad = 'Media'
        Referencia = 'CIS 2.3.9.2' }
    $rec = 'GPO: Microsoft network server: Digitally sign communications (always) = Enabled.'
    try {
        $requerida = $null
        try { $requerida = (Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature }
        catch { $requerida = (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature') -eq 1 }
        if ($requerida) { return New-Resultado @p -Estado OK -Detalle 'RequireSecuritySignature = True' }
        $estado = if (Test-EsServidor) { 'FALLO' } else { 'AVISO' }
        return New-Resultado @p -Estado $estado -Detalle 'La firma SMB no es obligatoria.' -Recomendacion $rec
    }
    catch {
        return New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}

function Test-Llmnr {
    $p = @{ Id = 'RED-03'; Categoria = 'Red'; Nombre = 'LLMNR desactivado'; Severidad = 'Media'
        Referencia = 'CIS 18.6.4.x (Turn off multicast name resolution)' }
    $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast'
    if ($v -eq 0) { return New-Resultado @p -Estado OK -Detalle 'EnableMulticast = 0 (por directiva)' }
    New-Resultado @p -Estado FALLO -Detalle 'LLMNR activo: permite capturar credenciales en la red local (ataques tipo Responder).' `
        -Recomendacion 'GPO: Configuración del equipo > Plantillas administrativas > Red > Cliente DNS > Desactivar resolución de nombres de multidifusión = Habilitada.'
}

function Test-NetBios {
    $p = @{ Id = 'RED-04'; Categoria = 'Red'; Nombre = 'NetBIOS sobre TCP/IP desactivado'; Severidad = 'Baja'
        Referencia = 'Endurecimiento frente a NBT-NS poisoning' }
    try {
        $ifs = @(Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction Stop |
                Where-Object { $_.PSChildName -like 'Tcpip_*' })
        if ($ifs.Count -eq 0) { return New-Resultado @p -Estado NO_COMPROBADO -Detalle 'No se encontraron interfaces NetBT.' }
        $activas = @($ifs | Where-Object { (Get-RegValue -Path $_.PSPath -Name 'NetbiosOptions') -ne 2 })
        if ($activas.Count -eq 0) { return New-Resultado @p -Estado OK -Detalle "NetBIOS desactivado en las $($ifs.Count) interfaces." }
        New-Resultado @p -Estado AVISO -Detalle "NetBIOS no está desactivado en $($activas.Count) de $($ifs.Count) interfaces." `
            -Recomendacion 'Desactívalo en las propiedades IPv4 > Avanzadas > WINS, o por DHCP (opción 001 de Microsoft).'
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}

function Test-Rdp {
    $p = @{ Id = 'RED-05'; Categoria = 'Red'; Nombre = 'Escritorio remoto con NLA'; Severidad = 'Alta'
        Referencia = 'CIS 18.10.57.3.9.4 (Require user authentication for remote connections by using NLA)' }
    $deny = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections'
    if ($deny -eq 1) { return New-Resultado @p -Estado OK -Detalle 'El escritorio remoto está desactivado.' }
    $nla = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication'
    if ($nla -eq 1) { return New-Resultado @p -Estado OK -Detalle 'Escritorio remoto activado con autenticación a nivel de red (NLA).' }
    New-Resultado @p -Estado FALLO -Detalle 'Escritorio remoto activado SIN NLA: cualquiera ve la pantalla de inicio de sesión antes de autenticarse.' `
        -Recomendacion 'Propiedades del sistema > Remoto > "Permitir solo conexiones desde equipos con NLA", o la GPO equivalente.'
}

function Test-Cortafuegos {
    $p = @{ Id = 'RED-06'; Categoria = 'Red'; Nombre = 'Cortafuegos activo en todos los perfiles'; Severidad = 'Alta'
        Referencia = 'CIS 9.1.1 / 9.2.1 / 9.3.1' }
    try {
        $perfiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $apagados = @($perfiles | Where-Object { -not $_.Enabled } | ForEach-Object { $_.Name })
        if ($apagados.Count -eq 0) { return New-Resultado @p -Estado OK -Detalle 'Dominio, Privado y Público activos.' }
        New-Resultado @p -Estado FALLO -Detalle ("Perfiles apagados: " + ($apagados -join ', ')) `
            -Recomendacion 'Activa el cortafuegos en todos los perfiles y abre solo los puertos necesarios con reglas concretas.'
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}
