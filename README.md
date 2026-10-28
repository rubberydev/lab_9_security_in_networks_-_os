# Práctica 4 — Integradora · Guía de solución (Endurecer → Verificar)

**Maestría en Ciberseguridad · ITM — Seguridad de Redes y Sistemas Operativos**
**Docente: Paula Maya Arango**

> **Qué es "el resultado esperado".** En P4 el entregable principal **no** es el ataque, sino la prueba de que el control funciona: con todos los controles aplicados, se vuelven a lanzar los ataques desde Kali (192.168.100.10) y **todos deben fallar**. Esta guía da, por estación, el **control a aplicar**, el **re-ataque de verificación** y la **evidencia esperada** (el resultado negativo). Sirve como clave de respuestas para calificar y como solucionario para los equipos que entregaron solo la fase ofensiva.

Entorno: Ubuntu `192.168.100.20` · DC `avior.local` `192.168.100.30` · Win11 `192.168.100.40` · Kali atacante `192.168.100.10`.

---

## SESIÓN 1 — Linux (Ubuntu 192.168.100.20)

### L-1 · Credencial débil en SSH — fuerza bruta (Hydra) · T1110.001

**Control (en Ubuntu):**

1. **Bloqueo de cuenta** con `pam_faillock` — `/etc/security/faillock.conf`:
   ```
   deny = 5
   unlock_time = 900
   fail_interval = 900
   ```
   y en `/etc/pam.d/common-auth`:
   ```
   auth    required      pam_faillock.so preauth silent deny=5 unlock_time=900
   auth    [default=die] pam_faillock.so authfail        deny=5 unlock_time=900
   account required      pam_faillock.so
   ```
2. **Política de contraseñas** con `pam_pwquality` (`minlen=14`, `minclass=3`) y caducidad con `chage`.
3. **Endurecer SSH** (`/etc/ssh/sshd_config`): `PasswordAuthentication no` (autenticación por clave), `PermitRootLogin no`, `MaxAuthTries 3`, `AllowUsers`. Opcional: `fail2ban` jail `sshd`.

**Verificación (re-ataque desde Kali):**
```bash
hydra -l maria -P rockyou.txt ssh://192.168.100.20
```
**Evidencia esperada:** `0 valid passwords found`; en Ubuntu `sudo faillock --user maria` muestra la cuenta bloqueada. (Para reusar el lab: `sudo faillock --user maria --reset`.)

---

### L-2 · Reverse shell — payload + sesión interactiva · T1059.004

Este es el vector que ambos equipos resolvieron con `msfvenom` + `multi/handler`. Se cierra por **dos lados**: impedir la **ejecución** del payload y bloquear la **conexión saliente**.

**Control (en Ubuntu):**

1. **`/tmp` y directorios escribibles sin ejecución** — en `/etc/fstab`:
   ```
   /tmp      /tmp      ext4  defaults,noexec,nosuid,nodev  0 0
   /var/tmp  /var/tmp  none  bind,noexec,nosuid,nodev      0 0
   ```
   (o `tmpfs`). Remontar: `sudo mount -o remount /tmp`. Esto es lo que produce el `Permission denied` al intentar correr el binario desde `/tmp`.
2. **Filtrado de salida (egress) por defecto-denegar** — el informe del Equipo A notó que "el firewall no detectó la conexión saliente porque por defecto se permite el tráfico de salida". Con `nftables`/`ufw`:
   ```bash
   sudo ufw default deny outgoing
   sudo ufw allow out 53,80,443/tcp     # solo lo necesario
   sudo ufw enable
   ```
3. Opcional: perfil **AppArmor** sobre el servicio expuesto.

**Verificación (re-ataque):** volver a descargar y ejecutar el payload desde la sesión de `maria`, y dejar el `multi/handler` escuchando en Kali.
**Evidencia esperada:** al ejecutar en `/tmp` → `bash: ./shell: Permission denied`; el `multi/handler` **no recibe sesión**; el log de `ufw` registra el intento de salida bloqueado (`[UFW BLOCK] … DST=192.168.100.10`). Par antes/después = una captura con la sesión Meterpreter abierta (estado P1) y otra con el handler vacío + `Permission denied` (estado endurecido).

---

### L-3 · Escalada por abuso de SUID (`find`) · T1548.001

**Control (en Ubuntu):**

1. **Inventariar y quitar el SUID**:
   ```bash
   find / -perm -4000 -type f 2>/dev/null | tee suid-despues.txt
   sudo chmod u-s /usr/bin/find
   ```
   Comparar contra la línea base: `diff suid-antes.txt suid-despues.txt`.
2. **Sanear `sudoers`** (`sudo visudo`): quitar `NOPASSWD`, binarios peligrosos (`vim`, `find`, `python`, `less`…) y `ALL=(ALL)` innecesarios. Referencia del por qué: GTFOBins.

**Verificación (re-ataque desde la sesión de `maria`):**
```bash
find . -exec /bin/sh -p \; -quit      # truco GTFOBins sobre find
id
```
**Evidencia esperada:** `id` dentro del shell resultante muestra **`euid≠0`** (no hay root); `diff suid-antes.txt suid-despues.txt` evidencia el bit `s` removido de `/usr/bin/find`.

---

### Verificación final — Sesión 1 (tabla entregable)

| Estación | Ataque | Control aplicado | Re-ataque | Resultado esperado |
|---|---|---|---|---|
| L-1 | Hydra SSH | faillock + claves | `hydra … ssh://…20` | 0 valid / cuenta bloqueada ✅ |
| L-2 | Reverse shell | `/tmp` noexec + egress deny | payload + handler | Sin sesión + `Permission denied` ✅ |
| L-3 | SUID `find` | `chmod u-s` + sudoers | truco GTFOBins | `euid≠0`, sin root ✅ |

---

## SESIÓN 2 — Windows Server / Active Directory

### W-1 · Envenenamiento LLMNR/NBT-NS (Responder) → hash NTLMv2 · T1557.001

**Control (GPO en el DC):**

1. **Apagar LLMNR**: *Computer Config → Admin Templates → Network → DNS Client → "Turn Off Multicast Name Resolution" = Enabled*.
2. **Apagar NBT-NS**: por NIC (TCP/IP → WINS → *Disable NetBIOS over TCP/IP*) o vía DHCP opción 001.
3. **Exigir firma SMB**: *Microsoft network server: Digitally sign communications (always) = Enabled*.
   ```powershell
   Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
   ```

**Verificación:**
```bash
responder -I eth0 -w          # (nota: -r/-d quedaron deprecados; usar -w análisis)
nmap --script smb2-security-mode -p445 192.168.100.30
```
**Evidencia esperada:** Responder **sin captura** de hash; `nmap` reporta *message signing required*; `Get-ADDefaultDomainPasswordPolicy` documentado.

---

### W-2 · Kerberoasting de cuenta de servicio con SPN (`svc-backup`) · T1558.003

**Control (en el DC):** reemplazar la cuenta de servicio por una **gMSA** (contraseña gestionada de 120 caracteres, rotación automática → no crackeable) y retirar el SPN de la cuenta vulnerable.
```powershell
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))   # solo una vez en el lab
New-ADServiceAccount -Name svc-backup-gmsa -DNSHostName backup.avior.local `
  -ServicePrincipalNames "HTTP/backup.avior.local" `
  -PrincipalsAllowedToRetrieveManagedPassword "DC-Grupo$"
Install-ADServiceAccount svc-backup-gmsa
Test-ADServiceAccount svc-backup-gmsa        # → True
Disable-ADAccount svc-backup                 # retirar la cuenta vieja
```

**Verificación:**
```bash
GetUserSPNs.py avior.local/cortiz:'Av10r2024!' -dc-ip 192.168.100.30 -request
hashcat -m 13100 nuevo_tgs.txt rockyou.txt
```
**Evidencia esperada:** `Test-ADServiceAccount = True`; Hashcat **agota el diccionario sin resultado** sobre el TGS de la gMSA.

---

### W-3 · Movimiento lateral PSExec sobre SMB (`cortiz` admin local) · T1021.002

**Control (en el DC / estaciones):**

1. **Revocar admin local** de `cortiz` (least privilege); gestionar admin local con **LAPS**.
   ```powershell
   Remove-LocalGroupMember -Group "Administradores" -Member "AVIOR\cortiz"
   ```
2. **Deshabilitar SMBv1:**
   ```powershell
   Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
   Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
   ```

**Verificación:**
```bash
crackmapexec smb 192.168.100.30 -u cortiz -p 'Av10r2024!'
```
**Evidencia esperada:** la línea ya **no muestra `(Pwn3d!)`** (solo autenticación o acceso denegado); `Get-SmbServerConfiguration | select EnableSMB1Protocol` → `False`.

---

### W-4 · Volcado de LSASS / Mimikatz (`cmejia` en Domain Admins) · T1003.001

**Control (en el DC):**

1. **Apagar WDigest** (sin texto claro en memoria):
   `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` → `UseLogonCredential = 0`.
2. **LSASS como proceso protegido (RunAsPPL)** — requiere reinicio:
   `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` → `RunAsPPL = 1`.
3. **Protected Users**: agregar `cmejia` y demás Domain Admins.
   ```powershell
   Add-ADGroupMember "Protected Users" -Members cmejia
   ```
4. Donde aplique: **Credential Guard** (VBS).

**Verificación (desde una sesión Meterpreter previa en el DC):**
```
load kiwi
creds_all
```
**Evidencia esperada:** `UseLogonCredential=0` en el registro; `cmejia` dentro de *Protected Users*; `creds_all` **sin texto claro** (WDigest vacío) y, con RunAsPPL activo, Mimikatz no abre LSASS sin driver (`ERROR kuhl_m_sekurlsa_acquireLSA ; Handle … 0x5`).

---

### W-5 · Abuso de ACL → ruta a Domain Admin (BloodHound) · T1087.002

**Control (en el DC):** localizar y eliminar la ACE abusiva. En el lab, el camino era `cortiz → IT_Group → [GenericAll] → cmejia → Domain Admins`.
```powershell
# Localizar
Get-ADUser cmejia -Properties nTSecurityDescriptor
# (o PowerView) Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -eq 'IT_Group'}
# Eliminar el GenericAll de IT_Group sobre cmejia
dsacls "CN=cmejia,OU=...,DC=avior,DC=local" /R "AVIOR\IT_Group"
```
Aplicar least privilege sobre OUs y grupos.

**Verificación:**
```bash
bloodhound-python -u cortiz -p 'Av10r2024!' -d avior.local -dc 192.168.100.30 -c All
# En la GUI: "Find Shortest Paths to Domain Admins"
```
**Evidencia esperada:** grafo ANTES con el camino de 2 saltos y DESPUÉS **sin ruta** desde `cortiz` a Domain Admins.

---

### W-6 · Montar la detección (auditoría) · T1562 (defensa)

**Control (GPO de auditoría avanzada en el DC):** habilitar *Advanced Audit Policy* — Logon/Logoff, Account Logon (Kerberos), Credential Validation, Detailed Tracking, Object Access; y **PowerShell Script Block Logging** (evento 4104). Opcional: Sysmon.

**Mapa evento ↔ ataque (evidencia de W-6):**

| Evento | Significado | Ataque que delata |
|---|---|---|
| 4625 | Fallo de inicio de sesión | Fuerza bruta SSH/SMB (L-1, W-3) |
| 4768 / 4769 | TGT / TGS solicitado (RC4 = 0x17) | Kerberoasting (W-2) |
| 4648 | Logon con credenciales explícitas | Pass-the-Hash / lateral (W-3, W-4) |
| 4672 | Privilegios especiales asignados | Sesión SYSTEM/admin (W-3) |
| 7045 / 4697 | Instalación de servicio | PSExec (W-3) |
| 4104 | Bloque de script PowerShell | Ejecución ofensiva post-explotación |

---

### Verificación final — Sesión 2 (tabla entregable)

| Estación | Ataque | Control | Re-ataque | Resultado esperado |
|---|---|---|---|---|
| W-1 | Responder NTLMv2 | GPO LLMNR/NBT off + firma SMB | `responder` / `nmap` | Sin captura; signing required ✅ |
| W-2 | Kerberoasting | gMSA + retirar SPN | `GetUserSPNs` + `hashcat` | Diccionario agotado ✅ |
| W-3 | PSExec SMB | Revocar admin + SMBv1 off | `crackmapexec` | Sin `(Pwn3d!)` ✅ |
| W-4 | Mimikatz LSASS | WDigest 0 + RunAsPPL + Protected Users | `kiwi creds_all` | Sin texto claro ✅ |
| W-5 | ACL → DA | Eliminar ACE abusiva | BloodHound | Sin ruta a DA ✅ |
| W-6 | (detección) | Auditoría avanzada por GPO | Relanzar ataques | Eventos registrados ✅ |

---

