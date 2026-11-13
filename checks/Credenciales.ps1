# Comprobaciones de protección de credenciales. Solo lectura.

function Test-LmCompat {
    $p = @{ Id = 'CRD-01'; Categoria = 'Credenciales'; Nombre = 'Nivel de autenticación LAN Manager (solo NTLMv2)'; Severidad = 'Alta'
        Referencia = 'CIS 2.3.11.7' }
    $rec = 'GPO: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM (valor 5).'
    $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
    if ($null -eq $v) {
        return New-Resultado @p -Estado AVISO -Detalle 'Valor no definido: Windows usa 3 por defecto (envía NTLMv2 pero acepta LM y NTLM).' -Recomendacion $rec
    }
    if ($v -ge 5) { return New-Resultado @p -Estado OK -Detalle "LmCompatibilityLevel = $v" }
    if ($v -ge 3) { return New-Resultado @p -Estado AVISO -Detalle "LmCompatibilityLevel = $v" -Recomendacion $rec }
    New-Resultado @p -Estado FALLO -Detalle "LmCompatibilityLevel = $v (permite enviar LM o NTLMv1)" -Recomendacion $rec
}

function Test-WDigest {
    $p = @{ Id = 'CRD-02'; Categoria = 'Credenciales'; Nombre = 'WDigest sin contraseñas en memoria'; Severidad = 'Alta'
        Referencia = 'Microsoft KB2871997 / MITRE T1003.001' }
    $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential'
    if ($v -eq 1) {
        return New-Resultado @p -Estado FALLO -Detalle 'UseLogonCredential = 1: las contraseñas quedan en claro en memoria (Mimikatz las lee).' `
            -Recomendacion 'Pon UseLogonCredential = 0 o elimina el valor. Revisa por qué se activó: suele ser señal de compromiso.'
    }
    New-Resultado @p -Estado OK -Detalle 'UseLogonCredential no está activado.'
}

function Test-ProteccionLsa {
    $p = @{ Id = 'CRD-03'; Categoria = 'Credenciales'; Nombre = 'Protección LSA (RunAsPPL)'; Severidad = 'Media'
        Referencia = 'Microsoft: Configure added LSA protection' }
    $v = Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL'
    if ($v -in @(1, 2)) { return New-Resultado @p -Estado OK -Detalle "RunAsPPL = $v" }
    New-Resultado @p -Estado AVISO -Detalle 'La protección LSA no está activada.' `
        -Recomendacion 'Actívala por GPO (Configure LSASS to run as a protected process). Prueba antes los controladores y plugins de seguridad.'
}

function Test-CredentialGuard {
    $p = @{ Id = 'CRD-04'; Categoria = 'Credenciales'; Nombre = 'Credential Guard en ejecución'; Severidad = 'Baja'
        Referencia = 'Microsoft: Credential Guard overview' }
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        if (@($dg.SecurityServicesRunning) -contains 1) { return New-Resultado @p -Estado OK -Detalle 'Credential Guard está en ejecución.' }
        New-Resultado @p -Estado AVISO -Detalle 'Credential Guard no está en ejecución.' `
            -Recomendacion 'Requiere UEFI, arranque seguro y virtualización. Se activa por GPO (Turn On Virtualization Based Security).'
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}
