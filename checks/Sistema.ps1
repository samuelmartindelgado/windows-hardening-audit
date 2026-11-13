# Comprobaciones del sistema. Solo lectura.

$script:MsgAdmin = 'Requiere ejecutar como administrador.'

function Test-Uac {
    $p = @{ Id = 'SIS-01'; Categoria = 'Sistema'; Nombre = 'Control de cuentas de usuario (UAC) activado'; Severidad = 'Alta'
        Referencia = 'CIS 2.3.17.6' }
    $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    if ($v -eq 0) {
        return New-Resultado @p -Estado FALLO -Detalle 'EnableLUA = 0: todo se ejecuta con privilegios completos.' -Recomendacion 'Activa UAC (EnableLUA = 1) y reinicia.'
    }
    New-Resultado @p -Estado OK -Detalle 'UAC activado.'
}

function Test-Antivirus {
    $p = @{ Id = 'SIS-02'; Categoria = 'Sistema'; Nombre = 'Antivirus con protección en tiempo real y firmas al día'; Severidad = 'Alta'
        Referencia = 'CIS Control 10' }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        if (-not $mp.RealTimeProtectionEnabled) {
            return New-Resultado @p -Estado FALLO -Detalle 'Microsoft Defender: protección en tiempo real desactivada.' -Recomendacion 'Actívala o confirma que hay otro antivirus gestionado.'
        }
        if ($mp.AntivirusSignatureAge -gt 3) {
            return New-Resultado @p -Estado AVISO -Detalle "Firmas con $($mp.AntivirusSignatureAge) días." -Recomendacion 'Revisa por qué no se actualizan (WSUS, proxy, servicio).'
        }
        New-Resultado @p -Estado OK -Detalle "Microsoft Defender activo, firmas con $($mp.AntivirusSignatureAge) día(s)."
    }
    catch {
        $otros = ''
        try {
            $av = @(Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { $_.displayName })
            if ($av.Count -gt 0) { $otros = ' Antivirus registrados: ' + ($av -join ', ') }
        }
        catch { $otros = '' }
        New-Resultado @p -Estado NO_COMPROBADO -Detalle ('No se pudo consultar Defender.' + $otros)
    }
}

function Test-BitLocker {
    $p = @{ Id = 'SIS-03'; Categoria = 'Sistema'; Nombre = 'BitLocker en la unidad del sistema'; Severidad = 'Media'
        Referencia = 'CIS 18.10.9.x' }
    if (-not (Test-EsAdmin)) { return New-Resultado @p -Estado NO_COMPROBADO -Detalle $script:MsgAdmin }
    try {
        $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ("$($vol.ProtectionStatus)" -eq 'On') { return New-Resultado @p -Estado OK -Detalle "Cifrado: $($vol.EncryptionMethod)" }
        $estado = 'FALLO'
        if (Test-EsServidor) { $estado = 'AVISO' }
        New-Resultado @p -Estado $estado -Detalle "Protección: $($vol.ProtectionStatus)" -Recomendacion 'Cifra la unidad y guarda la clave de recuperación en AD o Entra ID.'
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}

function Test-Actualizaciones {
    $p = @{ Id = 'SIS-04'; Categoria = 'Sistema'; Nombre = 'Actualizaciones recientes'; Severidad = 'Alta'
        Referencia = 'CIS Control 7' }
    try {
        $fechas = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | ForEach-Object { [datetime]$_.InstalledOn })
        if ($fechas.Count -eq 0) { return New-Resultado @p -Estado NO_COMPROBADO -Detalle 'Get-HotFix no devolvió fechas.' }
        $ultima = ($fechas | Sort-Object -Descending)[0]
        $dias = [int]((Get-Date) - $ultima).TotalDays
        $det = "Última actualización instalada: $($ultima.ToString('yyyy-MM-dd')) (hace $dias días)."
        if ($dias -gt 90) { return New-Resultado @p -Estado FALLO -Detalle $det -Recomendacion 'Revisa Windows Update o WSUS: el equipo lleva meses sin parches.' }
        if ($dias -gt 45) { return New-Resultado @p -Estado AVISO -Detalle $det -Recomendacion 'Comprueba que el equipo recibe los parches mensuales.' }
        New-Resultado @p -Estado OK -Detalle $det
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}

function Test-ReinicioPendiente {
    $p = @{ Id = 'SIS-05'; Categoria = 'Sistema'; Nombre = 'Sin reinicio pendiente'; Severidad = 'Baja'
        Referencia = 'Buenas prácticas de parcheo' }
    $motivos = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $motivos += 'Component Based Servicing' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $motivos += 'Windows Update' }
    if (Get-RegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations') { $motivos += 'Ficheros pendientes de renombrar' }
    if ($motivos.Count -eq 0) { return New-Resultado @p -Estado OK -Detalle 'No hay reinicios pendientes.' }
    New-Resultado @p -Estado AVISO -Detalle ('Reinicio pendiente por: ' + ($motivos -join ', ')) -Recomendacion 'Reinicia en la próxima ventana de mantenimiento: algunos parches no se aplican hasta entonces.'
}

function Test-PowerShellV2 {
    $p = @{ Id = 'SIS-06'; Categoria = 'Sistema'; Nombre = 'PowerShell 2.0 desinstalado'; Severidad = 'Media'
        Referencia = 'CIS 18.10.x / evita saltarse el registro de scripts' }
    if (-not (Test-EsAdmin)) { return New-Resultado @p -Estado NO_COMPROBADO -Detalle $script:MsgAdmin }
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName 'MicrosoftWindowsPowerShellV2Root' -ErrorAction Stop
        if (-not $f -or "$($f.State)" -ne 'Enabled') { return New-Resultado @p -Estado OK -Detalle 'PowerShell 2.0 no está habilitado.' }
        New-Resultado @p -Estado AVISO -Detalle 'PowerShell 2.0 habilitado: permite ejecutar scripts sin AMSI ni registro.' `
            -Recomendacion 'Quita la característica MicrosoftWindowsPowerShellV2Root.'
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}

function Test-ArranqueSeguro {
    $p = @{ Id = 'SIS-07'; Categoria = 'Sistema'; Nombre = 'Arranque seguro (Secure Boot)'; Severidad = 'Media'
        Referencia = 'Microsoft: Secure Boot' }
    if (-not (Test-EsAdmin)) { return New-Resultado @p -Estado NO_COMPROBADO -Detalle $script:MsgAdmin }
    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) { return New-Resultado @p -Estado OK -Detalle 'Arranque seguro activado.' }
        New-Resultado @p -Estado AVISO -Detalle 'UEFI sin arranque seguro.' -Recomendacion 'Actívalo en la BIOS/UEFI.'
    }
    catch {
        New-Resultado @p -Estado AVISO -Detalle 'No se pudo confirmar (equipo en modo BIOS heredado o sin soporte).' -Recomendacion 'Usa UEFI con arranque seguro cuando sea posible.'
    }
}

function Test-AutoRun {
    $p = @{ Id = 'SIS-08'; Categoria = 'Sistema'; Nombre = 'Reproducción automática desactivada'; Severidad = 'Baja'
        Referencia = 'CIS 18.10.7.3' }
    $v = Get-RegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun'
    if ($v -eq 255) { return New-Resultado @p -Estado OK -Detalle 'NoDriveTypeAutoRun = 255 (todas las unidades).' }
    New-Resultado @p -Estado AVISO -Detalle "NoDriveTypeAutoRun = $(if ($null -eq $v) { 'no definido' } else { $v })" `
        -Recomendacion 'GPO: Turn off Autoplay = Enabled, All drives.'
}

function Test-ColaImpresion {
    $p = @{ Id = 'SIS-09'; Categoria = 'Sistema'; Nombre = 'Cola de impresión en servidores'; Severidad = 'Media'
        Referencia = 'CVE-2021-34527 (PrintNightmare)' }
    try {
        $s = Get-Service -Name 'Spooler' -ErrorAction Stop
        $corre = "$($s.Status)" -eq 'Running'
        if (-not (Test-EsServidor)) { return New-Resultado @p -Estado OK -Detalle "Equipo cliente (Spooler: $($s.Status))." }
        if (-not $corre) { return New-Resultado @p -Estado OK -Detalle 'Spooler detenido en el servidor.' }
        New-Resultado @p -Estado AVISO -Detalle 'Spooler en ejecución en un servidor.' `
            -Recomendacion 'Si el servidor no imprime, desactívalo; en controladores de dominio, siempre.'
    }
    catch {
        New-Resultado @p -Estado NO_COMPROBADO -Detalle (Get-MensajeCorto $_)
    }
}
