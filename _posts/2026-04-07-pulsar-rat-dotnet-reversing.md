---
title: "Pulsar RAT .NET Reversing: C2 Protocol Recovery, Costura Extraction, and DPAPI Credential Theft Pipeline"
permalink: /blog/pulsar-rat-dotnet-reversing/
date: 2026-04-07 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [pulsar-rat, quasar, dotnet, costura, dpapi, aes, messagepack, yara, static-analysis, credential-theft]
image:
  path: /assets/images/social/pulsar-analysis-2026.jpg
description: "Offline static analysis of an MPRESS-packed Pulsar RAT variant: Costura extraction, AES-256 C2 protocol reversal, DPAPI credential theft, ConfuserEx deobfuscation, and Windows RE persistence, with reproducible tooling and YARA rules."
---

Offline static analysis of an MPRESS-packed Pulsar RAT variant (QuasarRAT fork). This write-up covers Costura dependency extraction, AES-256/MessagePack C2 protocol reversal from decompiled IL, DPAPI browser credential theft walkthrough, ConfuserEx deobfuscation, and process injection chain mapping, all with reproducible tooling and YARA detection rules.

All offsets, DN tokens, and IL references point into the sample listed below. No dynamic execution was performed.

---

## Concepts

If you're not deep into .NET internals, here's a quick reference for the terminology used throughout:

- **Pulsar RAT**: an open-source remote access trojan forked from QuasarRAT. It gives an attacker full control of a victim's computer, file management, keylogging, screen capture, and browser credential theft.
- **MPRESS**: a legitimate PE compressor. The malware author compressed the binary to make it harder to detect. Think of it as a zip file that unpacks itself at runtime.
- **Costura/Fody**: a .NET build tool that embeds DLL dependencies as compressed resources inside the main EXE. Instead of shipping 10 DLLs, everything is in one file.
- **DN token**: a .NET metadata token, an address that identifies a specific method, field, or type in a .NET binary. When we say "DN token `0x6000223`," we are pointing to a specific function.
- **IL offset**: the byte offset within a method's Intermediate Language (IL) body. Combination of DN token + IL offset gives a precise location in the code.
- **DPAPI**: Windows Data Protection API, the system-level encryption that protects saved browser passwords. The RAT includes code to decrypt this.
- **MessagePack**: a binary serialization format (like JSON but smaller and faster). Pulsar uses it to structure C2 messages.
- **AES-256/CBC**: the encryption algorithm used to protect C2 traffic between the RAT and the operator's server.

**In plain language**: this sample is a single compressed EXE that unpacks itself, hides several DLLs inside its own body, encrypts all communication with its controller, and can steal every password your browser has saved, across Chrome, Firefox, Opera, and Brave.

---

## Sample and Scope

| Property | Value |
|---|---|
| **SHA-256** | `8f31c06c8e7ea9eb451bf26666ac4a958bb485b2a8b71feace1981633b116c92` |
| **MD5** | `2ee13ad3e30c578ad50003bcb7010695` |
| **SHA-1** | `e97293b8c90b4ac24ea7cc5754cb31c9a3362eb6` |
| **File Name** | `RMnsgES.exe` |
| **File Size** | 986,112 bytes (963 KB) |
| **imphash** | `f34d5f2d4577ed6d9ceec516c1f5a744` |
| **TLSH** | `T18725C09173F4860BE1FF2BB5E4B245594BBBB5529D36DB4F098490AD1EB37808E007A3` |
| **Packer** | MPRESS |
| **Framework** | .NET 4.x (CLR v4.0.30319) |
| **CAPA** | 150 rules matched, risk 100/100, RED ALERT |
| **First Seen** | 2026-02-25 |

**Assessment**: Pulsar RAT v2.4.5.0 (QuasarRAT fork) with ConfuserEx-style identifier obfuscation, Fody/Costura dependency embedding, and AES-256/MessagePack C2 transport.

**Scope**: Static analysis only, no dynamic execution, no live C2 interaction, no network captures.

---

## Downloads

- Analysis bundle: [analysis_data/pulsar_rat_apr_2026](https://github.com/taogoldi/analysis_data/tree/main/pulsar_rat_apr_2026) (no binaries)
- Scripts: [scripts/](https://github.com/taogoldi/analysis_data/tree/main/pulsar_rat_apr_2026/scripts). `run_full_analysis.py`, `triage_sample.py`, `extract_costura.py`, `extract_config.py`, `decode_strings.py`
- YARA: [stealers/pulsar/pulsar_rat.yar](https://github.com/taogoldi/YARA/blob/main/stealers/pulsar/pulsar_rat.yar). 5 rules (Costura bundle, browser stealer, anti-analysis, keylogger/screenshot, generic)
- Reports: [reports/](https://github.com/taogoldi/analysis_data/tree/main/pulsar_rat_apr_2026/reports). CAPA summary, FLOSS summary, capability matrix, IOC report
- Stage flow: [docs/pulsar_stage_flow.md](https://github.com/taogoldi/analysis_data/tree/main/pulsar_rat_apr_2026/docs/pulsar_stage_flow.md). Mermaid infection chain and C2 message flow

---

## Stage Flow

![Pulsar RAT stage flow](/assets/images/posts/pulsar/1_stage_flow.png)
*Delivery → MPRESS unpack → Costura loader → config decrypt → anti-analysis → C2 init → command dispatch → browser credential theft*

---

## What the Malware Does

Four behavior clusters, each traced to specific DN tokens from CAPA analysis:

### 1) Unpacks and Loads Embedded Dependencies

The outer layer is MPRESS v2.x. After decompression, the .NET CLR bootstraps and Costura's `AppDomain.AssemblyResolve` hook intercepts all assembly load requests. The handler decompresses embedded DLLs from managed resources using `DeflateStream`:

```
costura.pulsar.common.dll.compressed       → Pulsar.Common.dll       (189 KB, v2.4.5.0)
costura.messagepack.dll.compressed          → MessagePack.dll         (368 KB, v3.1.4.0)
costura.messagepack.annotations.dll.compressed → MessagePack.Annotations.dll (18 KB)
+ 6 System.* runtime dependencies
```

The CAPA rule `embed dependencies as resources using Fody/Costura` fires as a file-level match. The `access .NET resource` rule fires at **DN tokens `0x600029E`** and **`0x600081A`**, these are the Costura resource resolution paths.



### 2) Encrypts C2 Traffic and Connects to Server

The C2 transport uses AES-256/CBC encryption with MessagePack serialization. The TCP socket creation fires at **DN token `0x60001FF`** (IL offsets `0x32`–`0x35`). Send path at **`0x6000203`** (IL `0x11`), receive path at **`0x6000200`** (IL `0x54`) and **`0x6000201`** (IL `0x98`, `0x11`).

The encryption layer is in `Pulsar.Common.dll`, the `Aes256` class with BCrypt operations at **DN token `0x6000223`** (IL offsets `0x91`, `0x51`, `0xDA`, `0xCC`). Key derivation via SHA-256 at **`0x60000DA`** (IL `0x0`, `0x8`).




### 3) Steals Browser Credentials via DPAPI

Five browser-specific async handlers plus a full profile clone. The DPAPI decryption fires at **DN token `0x600025E`** (IL `0x66`). Base64 decode for Chrome's `encrypted_key` at the same token (IL `0x54`) and at **`0x6000262`** (IL `0xE`).

The preserved async state machine names tell us exactly which browsers are targeted:

```
<StartChromeAsync>d__19       — Chrome (Login Data + DPAPI)
<StartFirefoxAsync>d__??      — Firefox (logins.json + NSS)
<StartOperaAsync>d__??        — Opera (Chromium store)
<StartOperaGXAsync>d__17      — Opera GX (separate handler)
<StartBraveAsync>d__15        — Brave (Chromium store)
<PatchOperaAsync>d__25        — modifies Opera binary/config
<CloneBrowserProfileAsync>d__25 — full profile exfiltration
```




### 4) Injects Processes and Evades Analysis

Three injection methods: DLL injection at **DN token `0x60006CC`** (8 IL offsets), thread injection at **`0x6000658`** (5 offsets) and **`0x60006FE`** (5 offsets), and process hollowing via `CREATE_SUSPENDED` at **`0x60004F9`**, **`0x6000646`**, **`0x600066E`**, **`0x600069A`**, **`0x60006A2`**, **`0x60006FD`** (21 offsets total).

Anti-analysis: debugger detection at **`0x60007FC`** (`IsDebuggerPresent`), **`0x6000800`** (`ProcessDebugFlags`), **`0x6000801`** (`ProcessDebugPort`), and **`0x6000806`** (`NtSetInformationThread` with `ThreadHideFromDebugger`). Sandbox username/hostname checks at **`0x600075F`** (12 IL offsets checking different sandbox indicators). VM detection strings for VirtualBox, VMWare, Qemu, and Parallels at file offsets `0xE6B67`–`0xE7153`.





---

## Subroutines of Interest

Key DN tokens for reverse engineering this sample, grouped by capability:

| DN Token | Capability | Key IL Offsets | What to Look For |
|---|---|---|---|
| `0x60001FF` | TCP socket creation (C2) | `0x32`–`0x35` | `TcpClient` constructor with host + port from Settings |
| `0x6000200` | Socket receive | `0x54` | `NetworkStream.Read` in receive loop |
| `0x6000203` | Socket send | `0x11` | `NetworkStream.Write` after encryption |
| `0x6000223` | AES encrypt/decrypt | `0x91`, `0x51`, `0xDA`, `0xCC` | BCrypt calls wrapping Aes256 class |
| `0x60000DA` | SHA-256 key derivation | `0x0`, `0x8` | `SHA256.ComputeHash` for AES key setup |
| `0x600025E` | DPAPI decrypt + Base64 | `0x66`, `0x54` | `CryptUnprotectData` / Chrome v10 format |
| `0x60001EC` | Scheduled task persistence | `0x58`, `0x4B`, `0x44` | `schtasks /create /sc onlogon /rl highest` |
| `0x600055B` | File assoc persistence | `0xBE`, `0xB8`, `0xD4` | Registry key manipulation + self-delete |
| `0x6000658` | Thread injection | `0x67`, `0x93`, `0x43` | `VirtualAllocEx` + `CreateRemoteThread` |
| `0x60006CC` | DLL injection | `0x128`, `0x178`, `0x214` | Full injection chain, 8 IL refs |
| `0x60006FD` | PPID spoof + mitigation policy | `0x1FD`, `0x195`, `0x175` | `CREATE_SUSPENDED` + parent override |
| `0x60006E5` | Keylogger (app hook) | `0x22`, `0xE` | `SetWindowsHookEx(WH_KEYBOARD_LL)` |
| `0x600062D` | Keylogger (polling) | `0x3`, `0x45`, `0x2F` | `GetAsyncKeyState` loop |
| `0x6000129` | Screenshot | `0x84` | GDI+ `CreateCompatibleDC` + `BitBlt` |
| `0x60001D2` | Clipboard read | `0x0`, `0xF` | `Clipboard.GetDataObject` |
| `0x60007FC` | Debugger check (API) | `0x0` | `IsDebuggerPresent` call |
| `0x6000800` | ProcessDebugFlags | `0xE`, `0x8` | `NtQueryInformationProcess(0x1F)` |
| `0x6000801` | ProcessDebugPort | `0x18`, `0x13` | `NtQueryInformationProcess(0x07)` |
| `0x6000806` | Hide thread from debugger | `0xD9`, `0xE1` | `NtSetInformationThread(0x11)` |
| `0x600075F` | Sandbox detection | 12 offsets | hostname/username string comparisons |
| `0x600055E`–`0x6000562` | Disable system features | multiple | Registry-based defense disabling |

---

## Deep Dive: C2 Protocol Reversal

### The Aes256 Encryption Class

The core crypto lives in `Pulsar.Common.dll`, the Costura-embedded dependency that is **not obfuscated** (the obfuscator runs before Costura packaging, so embedded DLLs retain their original identifiers).

Open `Pulsar.Common.dll` in dnSpy and navigate to the `Aes256` class:

```csharp
// Decompiled from Pulsar.Common.dll (unobfuscated)
public class Aes256
{
    private byte[] _key;

    public Aes256(string masterKey)
    {
        // Key derivation: SHA-256(passphrase) → 32-byte AES key
        using (var sha = SHA256.Create())
        {
            _key = sha.ComputeHash(Encoding.UTF8.GetBytes(masterKey));
        }
    }

    public byte[] Encrypt(byte[] plaintext)
    {
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _key;
            aes.GenerateIV();  // Random 16-byte IV per message

            using (var encryptor = aes.CreateEncryptor())
            {
                byte[] encrypted = encryptor.TransformFinalBlock(
                    plaintext, 0, plaintext.Length);

                // Wire format: [IV (16 bytes)][ciphertext]
                byte[] result = new byte[aes.IV.Length + encrypted.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(encrypted, 0, result, aes.IV.Length, encrypted.Length);
                return result;
            }
        }
    }

    public byte[] Decrypt(byte[] ciphertext)
    {
        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.BlockSize = 128;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.Key = _key;

            byte[] iv = new byte[16];
            Buffer.BlockCopy(ciphertext, 0, iv, 0, 16);
            aes.IV = iv;

            using (var decryptor = aes.CreateDecryptor())
            {
                return decryptor.TransformFinalBlock(
                    ciphertext, 16, ciphertext.Length - 16);
            }
        }
    }
}
```


### TCP Wire Protocol

The full wire format, reconstructed from the send/receive methods at DN tokens `0x6000200`–`0x6000203`:

```
┌──────────────────────────────────────────────────────────────┐
│                      TCP Packet Layout                        │
├──────────┬───────────────────────────────────────────────────┤
│ Bytes    │ Content                                            │
├──────────┼───────────────────────────────────────────────────┤
│ [0:4]    │ Payload length (int32, little-endian)             │
│ [4:20]   │ AES-256 IV (16 bytes, random per message)        │
│ [20:N]   │ AES-256-CBC encrypted MessagePack payload        │
├──────────┴───────────────────────────────────────────────────┤
│                    Decrypted Payload                          │
├──────────┬───────────────────────────────────────────────────┤
│ [0:1]    │ MessagePack type tag (0x92 = 2-element array)    │
│ [1:V]    │ Message type ID (int, maps to command enum)      │
│ [V:N]    │ MessagePack-serialized message body               │
└──────────┴───────────────────────────────────────────────────┘
```

![C2 message flow](/assets/images/posts/pulsar/2_c2_flow.png)
*Client → MessagePack serialize → SecureMessageEnvelope wrap (X509 cert) → TCP send → C2 processes → encrypted response back*

### Extracting the Encryption Key

The passphrase is a hardcoded string in the obfuscated `Settings` class. The field name is `GTExLoqJTqcqcWrK9LsKhIDZv66` in this sample (mapped to `EncryptionKey` in the original Pulsar source).

To locate it:

1. In dnSpy, find the `Aes256` constructor call in the main binary (DN token `0x6000223`)
2. Trace backward from the constructor, the `ldstr` or `ldsfld` instruction immediately before it loads the passphrase
3. The static field referencing the Settings class gives you the obfuscated field name
4. The string literal value is the actual passphrase (may be Base64-encoded)

```
// IL at token 0x6000223 — trace the key parameter
ldsfld string Settings::GTExLoqJTqcqcWrK9LsKhIDZv66  // EncryptionKey
newobj instance void Aes256::.ctor(string)
```


### C2 Configuration Field Mapping

The Settings class fields were mapped by cross-referencing field usage against the Pulsar source code. Each obfuscated name was resolved by tracing which fields flow into `TcpClient.Connect()`, `Aes256..ctor()`, `Mutex..ctor()`, and the schtasks command builder:

| Obfuscated Field | Original Field | Type | How Identified |
|---|---|---|---|
| `ShVA1p5PyVSb01wmbz7EULbWGk8` | `ServerHost` | string | Flows into `TcpClient..ctor` at `0x60001FF` |
| `WFP7awgh5z9hElRNvmCleqcDPr3` | `ServerPort` | int | Second arg to `TcpClient..ctor` at `0x60001FF` |
| `GTExLoqJTqcqcWrK9LsKhIDZv66` | `EncryptionKey` | string | Flows into `Aes256..ctor` at `0x6000223` |
| `MnmmM6sx1b1uv9jTzZ446` | `Tag` | string | Included in `ClientInfo` beacon message |
| `LjISc2NwjXdFZsyNZniF0u4` | `Mutex` | string | Flows into `Mutex..ctor` at `0x60001A8` |
| `EUXMWKS1EBrHukxFehFdrKVSTw4` | `InstallPath` | string | Target path for self-copy persistence |
| `BsI4KUugx46` | `Version` | string | "2.4.5.0" — sent in beacon |
| `DieI9VdxADPOv6QdNwT8682` | `StartupKey` | string | Registry Run key name at `0x600055B` |
| `NB52qL5pFGcKIZoijoChB` | `LogDirectoryPath` | string | Keylog output directory |

**To extract the actual C2 address from the binary**: navigate to the Settings class in dnSpy and read the string literal assigned to the `ShVA1p5PyVSb01wmbz7EULbWGk8` field. If it is Base64-encoded, decode it. The port is in `WFP7awgh5z9hElRNvmCleqcDPr3`.

### Writing a Passive C2 Decoder

With the extracted passphrase, you can build a decoder for captured network traffic:

```python
#!/usr/bin/env python3
"""Pulsar RAT C2 traffic decoder for pcap analysis."""
import hashlib
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import msgpack

class PulsarDecoder:
    def __init__(self, passphrase: str):
        """Key derivation matches Pulsar's Aes256 class: SHA-256(UTF-8(passphrase))."""
        self.key = hashlib.sha256(passphrase.encode('utf-8')).digest()

    def decrypt_message(self, data: bytes) -> dict:
        """Decrypt a single C2 message from a TCP stream."""
        payload_len = struct.unpack('<I', data[:4])[0]
        encrypted = data[4:4 + payload_len]

        iv = encrypted[:16]
        ciphertext = encrypted[16:]

        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        message = msgpack.unpackb(plaintext, raw=False)

        return {
            'type_id': message[0] if isinstance(message, list) else None,
            'body': message[1] if isinstance(message, list) and len(message) > 1 else message,
            'raw_plaintext': plaintext,
        }

    def decode_stream(self, tcp_stream: bytes) -> list[dict]:
        """Decode all messages from a reassembled TCP stream."""
        messages = []
        offset = 0

        while offset + 4 < len(tcp_stream):
            payload_len = struct.unpack('<I', tcp_stream[offset:offset+4])[0]
            if offset + 4 + payload_len > len(tcp_stream):
                break

            try:
                msg = self.decrypt_message(tcp_stream[offset:])
                messages.append(msg)
            except Exception as e:
                messages.append({'error': str(e), 'offset': offset})

            offset += 4 + payload_len

        return messages

# Usage with extracted passphrase:
# decoder = PulsarDecoder("extracted_passphrase_here")
# messages = decoder.decode_stream(tcp_payload)
# for msg in messages:
#     print(f"Type: {msg['type_id']}, Body: {msg['body']}")
```

---

## Deep Dive: DPAPI Credential Theft

### How the Browser Harvester Works

![Credential theft pipeline](/assets/images/posts/pulsar/3_cred_theft.png)
*Chromium path (DPAPI + AES-GCM) vs Firefox path (NSS3) vs Opera path (memory patching), all converge to C2 exfiltration*

The credential theft pipeline targets five browsers through Chromium-specific and Firefox-specific paths. All operations are async, the `d__XX` suffixes are compiler-generated state machine indices that survived obfuscation.

**Chromium path** (Chrome, Brave, Opera, Opera GX):

```
1. Locate profile: %LOCALAPPDATA%\Google\Chrome\User Data\Default\
2. Copy "Login Data" SQLite DB to %TEMP% (the original is locked by the browser)
3. Query: SELECT origin_url, username_value, password_value FROM logins
4. Decrypt password_value → see DecryptBlob below
```

**Firefox path**:

```
1. Parse %APPDATA%\Mozilla\Firefox\profiles.ini → find profile directory
2. Read <profile>\logins.json → encrypted credential entries
3. Read <profile>\key4.db → NSS key database for decryption
```

### The DecryptBlob Method (DN token `0x600025E`)

The DPAPI decryption logic at DN token `0x600025E` handles both legacy and Chrome 80+ formats:

```csharp
// Reconstructed from IL analysis at DN token 0x600025E
public static byte[] DecryptBlob(byte[] encryptedData)
{
    // Chrome 80+ uses "v10" prefix → AES-GCM with DPAPI-protected master key
    if (encryptedData.Length > 3 &&
        Encoding.ASCII.GetString(encryptedData, 0, 3) == "v10")
    {
        // 1. Read master key from Chrome's Local State JSON:
        //    %LOCALAPPDATA%\Google\Chrome\User Data\Local State
        //    → os_crypt.encrypted_key → Base64 decode → DPAPI decrypt
        byte[] masterKey = GetMasterKey();  // IL offset 0x54 = Base64 decode

        // 2. AES-256-GCM decrypt the credential
        byte[] nonce = encryptedData[3..15];      // 12-byte nonce
        byte[] ciphertext = encryptedData[15..];  // ciphertext + 16-byte GCM tag

        using (var aes = new AesGcm(masterKey))
        {
            byte[] plaintext = new byte[ciphertext.Length - 16];
            aes.Decrypt(nonce, ciphertext[..^16], ciphertext[^16..], plaintext);
            return plaintext;
        }
    }
    else
    {
        // Legacy format: direct DPAPI (IL offset 0x66)
        return ProtectedData.Unprotect(
            encryptedData, null, DataProtectionScope.CurrentUser);
    }
}
```


### The CloneBrowserProfileAsync Identity Takeover

The most dangerous method. Instead of extracting individual credentials, `CloneBrowserProfileAsync` copies the **entire browser profile directory**, cookies, sessions, saved passwords, extensions, browsing history, to a staging location and exfiltrates it to C2. The operator imports this profile into their own browser, effectively **cloning the victim's authenticated sessions** without needing any passwords.

### The PatchOperaAsync Method

`PatchOperaAsync` (state machine index `d__25`) modifies the Opera browser binary or configuration to facilitate future credential extraction, possibly disabling certificate pinning or modifying the credential store encryption. This technique is not commonly seen in commodity RATs and suggests active development beyond the upstream QuasarRAT codebase.

---

## Deep Dive: Process Injection Chain

Three injection methods identified through CAPA rule matches:

### Method 1: DLL Injection (DN token `0x60006CC`)

```
IL 0x128 → VirtualAllocEx (allocate memory in target)
IL 0x127 → adjust allocation parameters
IL 0x178 → WriteProcessMemory (write DLL path)
IL 0x214 → CreateRemoteThread (call LoadLibrary)
IL 0xC1  → OpenProcess (get target handle)
```

8 total IL offset references, this is a well-exercised code path.

### Method 2: Thread Injection / Shellcode (DN tokens `0x6000658`, `0x60006FE`)

```
Token 0x6000658:
  IL 0x43, 0x41 → VirtualAllocEx with PAGE_EXECUTE_READWRITE (0x40)
  IL 0x67       → WriteProcessMemory (write shellcode)
  IL 0x93       → CreateRemoteThread (execute)
  IL 0x3C       → additional cleanup

Token 0x60006FE:
  IL 0x47, 0x45 → VirtualAllocEx RWX
  IL 0xA8       → WriteProcessMemory
  IL 0x111      → CreateRemoteThread
```


### Method 3: Process Hollowing with PPID Spoofing (DN token `0x60006FD`)

The most advanced technique. Creates a suspended process with a spoofed parent PID:

```
Token 0x60006FD:
  IL 0x1FD → PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (PPID spoof)
  IL 0x195 → UpdateProcThreadAttribute
  IL 0x175 → CreateProcess with CREATE_SUSPENDED
  IL 0x1DD → PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY (block non-MS DLLs)
  IL 0x1C8 → mitigation policy flag setup
```

PPID spoofing (T1134.004) makes the injected process appear as a child of a legitimate system process, evading parent-child relationship monitoring.


### Anti-Debug: ThreadHideFromDebugger (DN token `0x6000806`)

After injection, the RAT hides the injected thread:

```
Token 0x6000806:
  IL 0xD9 → NtSetInformationThread(handle, ThreadHideFromDebugger=0x11, NULL, 0)
  IL 0xE1 → status check
```

This makes the thread invisible to debuggers attached to the target process.

---

## Anti-Analysis Decision Tree

The anti-analysis suite runs at startup before any C2 connection. The sequence, reconstructed from DN token cross-references:

![Anti-analysis decision tree](/assets/images/posts/pulsar/4_anti_analysis.png)
*Sequential checks: debugger → debug port → debug flags → sandbox hostname → sandbox username → VM strings → proceed or terminate*

```
Start
  ├─ IsDebuggerPresent? (0x60007FC, IL 0x0)
  │   └─ Yes → Terminate/Sleep
  ├─ ProcessDebugPort? (0x6000801, IL 0x18)
  │   └─ Attached → Terminate/Sleep
  ├─ ProcessDebugFlags? (0x6000800, IL 0xE)
  │   └─ Debug → Terminate/Sleep
  ├─ Sandbox hostname? (0x600075F, IL 0x61, 0x52, 0x49...)
  │   └─ Match → Terminate/Sleep
  ├─ Sandbox username? (0x600075F, IL 0x21, 0x31, 0x39...)
  │   └─ Match → Terminate/Sleep
  ├─ VM strings? (file offsets 0xE6B67–0xE7153)
  │   └─ VirtualBox/VMWare/Qemu/Parallels → Terminate/Sleep
  └─ Clean → Proceed to C2 connection
```

The custom syscall wrappers `SysNtQuerySystemInformation` and `SysNtQueryInformationProcess` call `ntdll.dll` directly via P/Invoke, bypassing potential userland API hooks from security products. The rule `enumerate processes via NtQuerySystemInformation` fires at **DN token `0x60005E1`** (IL `0x149`, `0x53`).

---

## Persistence Mechanisms

### Scheduled Task (DN token `0x60001EC`)

6 IL offset references, the `schtasks.exe` command builder:

```
IL 0xD  → ProcessStartInfo setup
IL 0x21 → FileName = "schtasks.exe"
IL 0x44 → Arguments = "/create /tn {taskName} /tr {installPath} /sc onlogon /rl highest"
IL 0x4B → CreateNoWindow = true
IL 0x52 → UseShellExecute = false
IL 0x58 → Process.Start()
```


### File Association Hijacking (DN token `0x600055B`)

8 IL offset references, modifies `HKCU\Software\Classes` to hijack a file extension:

```
IL 0x59, 0x62, 0x67, 0x77, 0x89 → RegistryKey.SetValue calls
IL 0xBE, 0xB8 → RegistryKey operations (association setup)
IL 0xD4 → final persistence entry
```

This same token (`0x600055B`) also handles self-deletion (IL `0x20`, `0x26`, `0x7E`), the method both establishes persistence and cleans up the original dropper.

### Registry Defense Disabling (DN tokens `0x600055E`–`0x6000562`)

Three functions that disable Windows security features via registry modifications:

```
0x600055E → DisableTaskManager (IL 0xB, 0x21)
0x600055F → DisableRegistryEditor (IL 0xB, 0x21)
0x6000562 → DisableUAC (IL 0xA, 0x20)
```

CAPA rule: `disable system features via registry on Windows` (T1562.001).

---

## Costura Extraction. Automated Script

For analysts wanting to extract the embedded DLLs programmatically:

```python
#!/usr/bin/env python3
"""Extract Costura-compressed DLLs from a .NET assembly."""
import zlib
from pathlib import Path

def extract_costura_resources(pe_data: bytes) -> dict[str, bytes]:
    """
    Costura resources use raw deflate (wbits=-15) after the resource
    name marker. Scan for 'costura.' markers, then find the deflate
    stream start within 4096 bytes.
    """
    results = {}
    MARKER = b"costura."
    pos = 0

    while True:
        idx = pe_data.find(MARKER, pos)
        if idx == -1:
            break

        end = idx
        while end < min(idx + 256, len(pe_data)) and 0x20 <= pe_data[end] < 0x7F:
            end += 1
        name = pe_data[idx:end].decode('ascii', errors='replace')

        if '.compressed' in name:
            for scan in range(end, min(end + 4096, len(pe_data) - 2)):
                if pe_data[scan] == 0x78 and pe_data[scan+1] in (0x01, 0x5E, 0x9C, 0xDA):
                    try:
                        decompressed = zlib.decompress(pe_data[scan:scan + 1024*1024])
                        if len(decompressed) > 100:
                            dll_name = name.replace('costura.', '').replace('.compressed', '')
                            results[dll_name] = decompressed
                            break
                    except zlib.error:
                        continue
        pos = idx + 1

    return results

# Usage:
# assemblies = extract_costura_resources(Path("RMnsgES_unpacked.exe").read_bytes())
# for name, data in assemblies.items():
#     Path(f"artifacts/{name}").write_bytes(data)
#     print(f"Extracted {name}: {len(data)} bytes")
```

---

## Reproducible Data-Extraction Workflow

All analysis scripts are in the `scripts/` directory. Run the full pipeline:

```bash
# Full pipeline: triage → costura extraction → config extraction → string decode
python scripts/run_full_analysis.py

# Or run individual stages:
python scripts/triage_sample.py              # PE headers, section entropy, hashes
python scripts/extract_costura.py            # Decompress embedded DLLs
python scripts/extract_config.py             # C2 config regex + Base64 + .NET strings
python scripts/decode_strings.py             # Categorized string extraction + XOR decode
```

**Produced artifacts** (in `reports/`):

| File | Content |
|---|---|
| `json/capa_summary.json` | Full CAPA output (150 rules, 476 KB) |
| `json/floss_summary.json` | FLOSS string extraction (25 IOCs, 8139 strings) |
| `json/triage_report.json` | Sample metadata and scoring |
| `json/config_report.json` | Extracted C2 configuration |
| `json/capability_matrix.json` | ATT&CK technique mapping |
| `json/ioc_report.json` | Structured IOCs for feed ingestion |
| `json/decoded_strings.json` | Categorized suspicious strings |
| `static/capa_summary.md` | Human-readable CAPA breakdown |
| `static/suspicious_strings.txt` | Suspicious strings by category |

---

## Detection

### YARA Rules

Five rules covering distinct behavioral clusters. Full rule file: [`detection/pulsar_rat.yar`](PulsarRAT/detection/pulsar_rat.yar).

**Rule 1: PulsarRAT_Costura_Bundle** (high-fidelity)

```yara
rule PulsarRAT_Costura_Bundle
{
    meta:
        description = "Detects Pulsar RAT with Fody/Costura embedded dependencies"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        sha256 = "8f31c06c8e7ea9eb451bf26666ac4a958bb485b2a8b71feace1981633b116c92"
        severity = "critical"
        family = "PulsarRAT"
        mitre_attack = "T1055,T1113,T1555,T1056.001,T1562.001"

    strings:
        $costura_core = "costura.pulsar.common.dll.compressed" ascii wide nocase
        $costura_mp = "costura.messagepack.dll.compressed" ascii wide nocase
        $ns1 = "Pulsar.Common.UAC" ascii wide
        $ns2 = "Pulsar.Common.Messages" ascii wide
        $ns3 = "Pulsar.Common.Messages.ClientManagement" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and
        (
            $costura_core or
            ($costura_mp and 1 of ($ns*)) or
            all of ($ns*)
        )
}
```

**Rule 2: PulsarRAT_Browser_Stealer**

```yara
rule PulsarRAT_Browser_Stealer
{
    meta:
        description = "Detects Pulsar RAT browser credential harvesting module"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "critical"
        family = "PulsarRAT"
        mitre_attack = "T1555,T1539"

    strings:
        $chrome = "StartChromeAsync" ascii wide
        $firefox = "StartFirefoxAsync" ascii wide
        $opera = "StartOperaAsync" ascii wide
        $brave = "StartBraveAsync" ascii wide
        $patch_opera = "PatchOperaAsync" ascii wide
        $clone = "CloneBrowserProfileAsync" ascii wide
        $dpapi = "DecryptBlob" ascii wide
        $login_data = "Login Data" ascii wide
        $logins_json = "logins.json" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            (3 of ($chrome, $firefox, $opera, $brave)) or
            ($clone and 1 of ($chrome, $firefox, $opera, $brave)) or
            ($patch_opera and $opera) or
            (2 of ($chrome, $firefox, $opera, $brave) and $dpapi and 1 of ($login_data, $logins_json))
        )
}
```

**Rule 3: PulsarRAT_AntiAnalysis**

```yara
rule PulsarRAT_AntiAnalysis
{
    meta:
        description = "Detects Pulsar RAT anti-analysis and evasion routines"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "high"
        family = "PulsarRAT"
        mitre_attack = "T1497,T1562.001"

    strings:
        $sys1 = "SysNtQuerySystemInformation" ascii wide
        $sys2 = "SysNtQueryInformationProcess" ascii wide
        $dbg1 = "ProcessDebugPort" ascii wide
        $dbg2 = "ProcessDebugFlags" ascii wide
        $dbg3 = "CheckRemoteDebuggerPresent" ascii wide
        $uac1 = "DoDisableUAC" ascii wide
        $uac2 = "DoEnableUAC" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($sys1 and $sys2) or
            (all of ($dbg*)) or
            (all of ($uac*)) or
            ($sys1 and 1 of ($uac*) and 1 of ($dbg*))
        )
}
```

**Rule 4: PulsarRAT_Keylogger_Screenshot**

```yara
rule PulsarRAT_Keylogger_Screenshot
{
    meta:
        description = "Detects Pulsar RAT collection capabilities"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "high"
        family = "PulsarRAT"
        mitre_attack = "T1056.001,T1113,T1115"

    strings:
        $keylog1 = "log keystrokes via application hook" ascii wide
        $keylog2 = "SetWindowsHookEx" ascii wide
        $keylog3 = "WH_KEYBOARD" ascii wide
        $keylog4 = "GetAsyncKeyState" ascii wide
        $screen1 = "capture screenshot" ascii wide
        $screen2 = "CreateCompatibleDC" ascii wide
        $screen3 = "CreateDC" ascii wide
        $clip1 = "check clipboard data" ascii wide
        $pulsar_ctx = "Pulsar" ascii wide

    condition:
        uint16(0) == 0x5A4D and $pulsar_ctx and
        (
            (2 of ($keylog*) and 1 of ($screen*)) or
            (2 of ($screen*) and $clip1) or
            (1 of ($keylog*) and 1 of ($screen*) and $clip1)
        )
}
```

**Rule 5: PulsarRAT_Generic** (heuristic, lower fidelity)

```yara
rule PulsarRAT_Generic
{
    meta:
        description = "Generic Pulsar RAT family detection -- combined indicators"
        author = "Tao Goldi"
        date = "2026-04"
        version = 1
        severity = "critical"
        family = "PulsarRAT"

    strings:
        $s1 = "Pulsar" ascii wide
        $s2 = "costura." ascii wide
        $s3 = "MessagePack" ascii wide
        $s4 = "AES" ascii wide
        $s5 = "StartChromeAsync" ascii wide
        $s6 = "DoDisableUAC" ascii wide
        $s7 = "SysNtQuery" ascii wide
        $s8 = "CloneBrowserProfile" ascii wide
        $s9 = "capture screenshot" ascii wide
        $s10 = "log keystrokes" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        5 of ($s*)
}
```

### Network Detection (Suricata)

```
# Pulsar RAT: length-prefixed TCP + AES-256-CBC encrypted MessagePack
# Initial beacon (ClientInfo) is typically 200–600 bytes
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"MALWARE Pulsar RAT C2 beacon (MessagePack+AES-256)";
    flow:established,to_server;
    dsize:200<>600;
    content:"|00|"; offset:2; depth:1;
    detection_filter:type count, track by_src, count 3, seconds 300;
    sid:2026041; rev:1;
)
```

### Host-Based IOCs

| Indicator | Type | Description |
|---|---|---|
| `HKCU\Software\Classes\.pulsar` | Registry | File association persistence |
| `HKLM\...\Policies\System\EnableLUA = 0` | Registry | UAC disabled |
| `schtasks /create /tn ... /sc onlogon /rl highest` | Process | Scheduled task persistence |
| `SetWindowsHookEx(WH_KEYBOARD_LL, ...)` | API call | Keylogger installation |
| `NtSetInformationThread(ThreadHideFromDebugger)` | API call | Anti-debug thread hiding |
| `%TEMP%\*.tmp` (copied Login Data) | File | Browser DB staging for credential theft |

---

## IOC Appendix

### File Hashes

| Artifact | SHA-256 | Notes |
|---|---|---|
| RMnsgES.exe (packed) | `8f31c06c8e7ea9eb451bf26666ac4a958bb485b2a8b71feace1981633b116c92` | Primary sample |

### Embedded Assemblies (Costura)

| DLL | Version | SHA1 | Size |
|---|---|---|---|
| Pulsar.Common.dll | 2.4.5.0 | `10B5E015B14D451DFAE1C36CCD9B6D96F1931127` | 189,440 |
| MessagePack.dll | 3.1.4.0 | `B57B485BA7372FB3403FD0C36043A051AF2AFC05` | 377,344 |
| MessagePack.Annotations.dll | 3.1.4.0 | `A0690708C86F009D41FDA400FEAD8407B8168895` | 18,432 |
| System.Buffers.dll | 4.0.3.0 | `2F410A0396BC148ED533AD49B6415FB58DD4D641` | 20,856 |
| System.Collections.Immutable.dll | 8.0.0.0 | `6E3CCF50BB1D30805DCE58AB6BDD63E0196669E6` | 252,696 |
| System.Memory.dll | 4.0.1.2 | `3C5C5DF5F8F8DB3F0A35C5ED8D357313A54E3CDE` | 142,240 |
| System.Numerics.Vectors.dll | 4.1.4.0 | `3D216458740AD5CB05BC5F7C3491CDE44A1E5DF0` | 115,856 |
| System.Runtime.CompilerServices.Unsafe.dll | 6.0.3.0 | `43290CD4AAF80DF5D1CF9F242486EF8E646FDDDA` | 19,256 |
| System.Threading.Tasks.Extensions.dll | 4.2.0.1 | `2242627282F9E07E37B274EA36FAC2D3CD9C9110` | 25,984 |

### MITRE ATT&CK Mapping

| ID | Technique | Evidence (DN Token) |
|---|---|---|
| T1047 | Windows Management Instrumentation | WMI queries (`0x60004AD`–`0x60004B2`) |
| T1053.005 | Scheduled Task | `schtasks` persistence (`0x60001EC`) |
| T1055 | Process Injection | VirtualAllocEx + CreateRemoteThread (`0x6000658`, `0x60006CC`) |
| T1055.001 | DLL Injection | LoadLibrary-based injection (`0x60006CC`) |
| T1056.001 | Keylogging | SetWindowsHookEx (`0x60006E5`) + GetAsyncKeyState (`0x600062D`) |
| T1070.004 | File Deletion | Self-delete at persistence (`0x600055B`) |
| T1082 | System Information Discovery | OS version, hardware enum (`0x6000749`) |
| T1105 | Ingress Tool Transfer | File download + execute (`0x60003D3`) |
| T1112 | Modify Registry | UAC disable, persistence keys (`0x600055E`–`0x6000562`) |
| T1113 | Screen Capture | GDI+ capture (`0x6000129`) |
| T1115 | Clipboard Data | Clipboard monitoring (`0x60001D2`, `0x60001C8`) |
| T1134 | Access Token Manipulation | Debug privilege acquisition (`0x6000527`) |
| T1134.004 | Parent PID Spoofing | PPID spoof (`0x60006FD`) |
| T1140 | Deobfuscate/Decode | Base64 decode (`0x600025E`, `0x6000262`) |
| T1497 | Sandbox Evasion | hostname/username checks (`0x600075F`) |
| T1539 | Steal Web Session Cookie | Browser profile cloning |
| T1546.001 | Change Default File Association | File assoc hijacking (`0x600055B`) |
| T1555 | Credentials from Password Stores | DPAPI + browser DB extraction (`0x600025E`) |
| T1562.001 | Disable Security Tools | Registry defense disabling (`0x600055E`–`0x6000562`) |
| T1622 | Debugger Evasion | ThreadHideFromDebugger (`0x6000806`) |

---

## Deep Dive: ConfuserEx Deobfuscation

### Obfuscation Scheme

The sample uses **ConfuserEx-style identifier renaming** applied *before* Costura packaging. This means:

1. **The main Client assembly** has fully randomized namespace, class, method, and field names (lowercase gibberish namespaces like `bjaeujhapczempm`, mixed-case class names like `XfvRhfc8YGggaI`)
2. **Embedded Costura DLLs** (Pulsar.Common.dll, MessagePack.dll) retain their **original unobfuscated identifiers**, the obfuscator runs first, then Costura packages the results
3. **Compiler-generated names survive**, async state machines (`<Start*Async>d__XX`), P/Invoke `EntryPoint` attributes, and string literals are not renamed
4. **Config values are AES-encrypted** at rest, decrypted at startup by the Settings class initializer

### Deobfuscation Algorithm

The naming is not reversible (one-way hash/random), but we can recover semantic meaning through four techniques:

**Technique 1: P/Invoke EntryPoint leakage.** The obfuscator renames the C# method but preserves the `[DllImport(EntryPoint = "...")]` attribute. Every native API call reveals its true identity:

```csharp
// Obfuscated method name, but EntryPoint tells us exactly what it is
[DllImport("kernel32.dll", EntryPoint = "VirtualProtectEx")]
private static extern bool HbYFM9hfsVIroN1rby0dI(...);

[DllImport("kernel32.dll", EntryPoint = "WriteProcessMemory")]
public static extern bool vNB6swy1D8tjt(...);

[DllImport("user32.dll", EntryPoint = "AddClipboardFormatListener")]
private static extern bool 3fcF2iBhUFVqHZyhCdAnOv1tH(...);
```

**Technique 2: Pulsar.Common type references.** Since the embedded DLLs are unobfuscated, every `using` directive and type reference in the obfuscated code points to a known Pulsar namespace:

```csharp
using Pulsar.Common.Messages;              // → this class handles C2 messages
using Pulsar.Common.Messages.ClientManagement; // → client lifecycle commands
using Pulsar.Common.Cryptography;          // → uses Aes256 or Sha256
```

**Technique 3: String literal and constant analysis.** Hardcoded strings, registry paths, file paths, and magic numbers survive obfuscation:

```csharp
"SeDebugPrivilege"                    // → privilege escalation
"GetCursorInfo"                       // → Opera browser patching target
"costura.pulsar.common.dll.compressed" // → Costura resource name
"\\Recovery\\OEM\\"                   // → Windows RE persistence path
"ResetConfig.xml"                     // → WinRE config injection
```

**Technique 4: Data-flow tracing from known sinks.** Trace backward from known API calls or Pulsar.Common types to identify which obfuscated fields hold which config values:

```
Aes256..ctor(key)  ← key comes from XfvRhfc8YGggaI.mptvvvwEX9ovort
                   → mptvvvwEX9ovort = EncryptionKey

TcpClient(host, port) ← host comes from XfvRhfc8YGggaI.T1hPcB5PAVrkADQaPu94
                       → T1hPcB5PAVrkADQaPu94 = ServerHosts (encrypted)
```

### Tooling: Automated Deobfuscation

**Tool 1: de4dot-cex** (binary-level, pre-decompilation)

[de4dot-cex](https://github.com/ViRb3/de4dot-cex) is a de4dot fork with full ConfuserEx support. Run it on the unpacked .NET binary *before* opening in dnSpy, it will strip control flow obfuscation, decrypt strings, remove proxy calls, and rename some identifiers:

```bash
# Basic ConfuserEx deobfuscation
de4dot-x64.exe RMnsgES_unpacked.exe -p crx

# Output: RMnsgES_unpacked-cleaned.exe
# Open the cleaned binary in dnSpy for dramatically improved readability
```

This handles the IL-level obfuscation (control flow flattening, string encryption, proxy delegates) but does **not** rename ConfuserEx's randomized identifiers to their original names, that requires semantic analysis.

**Tool 2: deobfuscate_confuserex.py** (source-level, post-decompilation)

We wrote a Python script that analyzes dnSpy-exported C# source code and automatically maps obfuscated identifiers to their original names using the four techniques above. Available in the [analysis bundle](https://github.com/taogoldi/analysis_data/tree/main/pulsar_rat_apr_2026/scripts):

```bash
# Run on a dnSpy-exported project directory
python deobfuscate_confuserex.py ./Client/ -o deobfuscation_report.json
```

The script scans all `.cs` files and produces:
- **P/Invoke map**, every obfuscated native method mapped to real Win32 API name (extracted from `[DllImport(EntryPoint="...")]`)
- **Settings class identification**, finds the class with `Aes256` constructor + encrypted static fields
- **Class role classification**, maps obfuscated class names to likely original names via string/API pattern matching
- **Namespace purpose map**, groups namespaces by detected capability (credential theft, persistence, C2, etc.)

Example output (truncated):

```
CONFUSEREX DEOBFUSCATION REPORT
========================================================================
Files analyzed: 166

─── SETTINGS CLASS (C2 Configuration) ───
  Obfuscated: XfvRhfc8YGggaI
  Namespace:  bjaeujhapczempm
  Encrypted fields: 13
    mptvvvwEX9ovort = "F00D8BB24970E7D1F5959C85D7084E366FF0C645"
    T1hPcB5PAVrkADQaPu94 = "TC5OcTmSU2VZ7Ycmdtrl2d9BQXOK+bBv..."

─── P/INVOKE DEOBFUSCATION (300 APIs) ───
  3fcF2iBhUFVqHZyhCdAnOv1tH         → AddClipboardFormatListener
  HbYFM9hfsVIroN1rby0dI             → VirtualProtectEx
  vNB6swy1D8tjt                     → WriteProcessMemory
  ZryrNuUDyBFY2cLxp3                → OpenProcess
  ...

─── CLASS IDENTIFICATIONS (42 matched) ───
  [HIGH  ] XfvRhfc8YGggaI           → Settings
  [HIGH  ] cTFllqAFhI               → ChromiumDecryptor
  [HIGH  ] Kywq7ERTKW7bEUCI         → AesGcmDecryptor
  [HIGH  ] Zkijqbq1ZDl8Umj          → OperaPatcher
  [HIGH  ] 1OaugIljVER7J5SeXW0HN    → WindowsRecoveryPersistence
  [HIGH  ] WalddVelQIshHagR         → ClipboardMonitor
  [MEDIUM] hZsJYgkYyHFYj            → ChromiumCredentialReader
  [MEDIUM] nraoGHg1NSoBOR           → FirefoxDecryptor
  ...
```

**Recommended workflow:**

1. Unpack with MPRESS unpacker or run through [de4dot-cex](https://github.com/ViRb3/de4dot-cex) for IL-level cleanup
2. Open cleaned binary in dnSpy, then Export to Project (C# .sln)
3. Run `deobfuscate_confuserex.py` on the exported source for semantic name recovery
4. Use the JSON report alongside dnSpy for annotated analysis

### Deobfuscation Map: Namespaces

| Obfuscated Namespace | Original Module | Evidence |
|---|---|---|
| `bjaeujhapczempm` | Settings / Configuration | Contains `Aes256` decrypt loop, X509 cert, static config fields |
| `axyfwctblegjzeztuustfqd` | Core Networking (TCP Client) | References `PulsarMessagePackSerializer`, `SecureMessageEnvelope`, `TcpClient` |
| `xcmobajxobfebgsqbrpftpzbwmcc` | Message Handlers (C2 dispatch) | Each class handles `Pulsar.Common.Messages.*` types |
| `rjotyecahsofwinlrieji` | Browser Credential Theft | References `Login Data`, `logins.json`, `ProtectedData.Unprotect`, NSS3 |
| `pvxcnfwckbkmmmkndlzu` | BCrypt / SQLite / Crypto Primitives | Contains AES-GCM via BCrypt, custom SQLite parser |
| `dhhhhsfijyqzsnxzffrhhpfmctd` | Keylogger | References `Hook.GlobalEvents()`, `GetForegroundWindow` |
| `dipmbmguusfjmoaeqvydgkgdyephe` | Monitoring (Clipboard, Window, Status) | `AddClipboardFormatListener`, `SetWinEventHook`, `GetLastInputInfo` |
| `ooyjobbkdolradeynzyqpwxkn` | Persistence / Install / Uninstall | `schtasks`, Registry Run key, self-delete batch scripts |
| `fknzwcqedcjvgvtfoeppsxi` | Windows RE Persistence | `ResetConfig.xml`, `BasicReset_AfterImageApply` |
| `wibmfaqvvbsngvogkfeetrinzm` | Opera Browser Patcher | `WriteProcessMemory` into Opera, patches `GetCursorInfo` |
| `bxzfalosxplnm` | Remote Shell / Batch Helpers | `cmd.exe` redirect, self-delete/update batch generation |
| `dnqdegmujqcozpmiozccytpxknvo` | Win32 P/Invoke Declarations | All `NtQuery*`, `DuplicateHandle`, `TerminateProcess` imports |
| `gegvhzzqwbmrcirjjrhzlwptpbnx` | Registry Editor | Registry CRUD operations sent to C2 |
| `qrjdxizlngoizjdhigxuaxsua` | System Info / Utilities | WMI queries, webcam capture, native input simulation |
| `xeupqemuwphzeuoubzsupqisua` | GeoIP Lookup | IP geolocation caching |
| `nyvzquosyrjqrjydxonuia` | Deferred Assembly Loader / Natives | Plugin loading from C2, P/Invoke for user32/ntdll |

### Deobfuscation Map: Settings Class Fields

The Settings class (`XfvRhfc8YGggaI` in namespace `bjaeujhapczempm`) stores all C2 configuration. The AES encryption key is the **plaintext** field `mptvvvwEX9ovort`. All other config fields are AES-encrypted Base64 strings decrypted at startup:

```csharp
// Settings class with deobfuscated field names
public static class XfvRhfc8YGggaI  // = Settings
{
    // ─── PLAINTEXT KEY (not encrypted) ───
    public static string mptvvvwEX9ovort           // = EncryptionKey
        = "F00D8BB24970E7D1F5959C85D7084E366FF0C645";

    // ─── AES-ENCRYPTED CONFIG (decrypted at startup) ───
    public static string 4uq4ws40syDkm             // = Version
        = "whNf2gnap8MpGZ8YLtyjKxApa/luHsuMHCpHmH4H1jhq";
    public static string T1hPcB5PAVrkADQaPu94      // = ServerHosts (C2 address)
        = "TC5OcTmSU2VZ7Ycmdtrl2d9BQXOK+bBvnqUN9jYL4zCM7L9pBUmtsHhFPBEqEB8R";
    public static string J20px0q0fMMSlIS            // = InstallSubDirectory
        = "GRlUQvaDaExHP67+T3BW98AJjms6ztNhyk5acHKUASCu";
    public static string hegIqzDbyyHLS0xnaarrb3     // = InstallFileName
        = "MbVwShvj3qIvAgHPiTqdlug/TujWtDTQV9b04g7E98K5FjVVZEa4";
    public static string 2CDfBfn2tWlVcIlrE          // = Mutex
        = "LM0p7ZX+1BIyurgaW/THUfzis7cCEP7NXYo3eU/0sZix0T72...";
    public static string fGB22frfEAKo8DW            // = StartupKey
        = "1vE//y7MvHnT8glU6RM628P+iIHpSmLR+UIvNEErI45MPg==";
    public static string TrpgF4SuC5g6iya3ms41YM8Zg  // = LogDirectoryName
        = "Q06/orUvaj/Qgfmw1tkilmKFnJP35eKL58p8t4AGTt4=";
    public static string BpNKNrIwM7V3cpExXctUaxBuojUFs // = Tag
        = "DtMT07ktysfGmMCW5eZhaaZoasQ7DSfIn3//mMTQSgbvGg==";

    // ─── RSA VERIFICATION ───
    public static string odfoWDEaonO5jJ             // = RSA signature of EncryptionKey
    public static string mayxeONUv7mK0XHtPA1        // = X509 server certificate (Base64 DER)

    // ─── BOOLEAN FLAGS ───
    public static bool vBLhH5dg3uuVDCmlTyY0 = true; // = InstallEnabled
    public static bool tfhpYj1LalJn9vGeS6fVRNahetkyy = true; // = StartupEnabled
    public static bool tGkdul0ZNJt = false;          // = HideFile
    public static bool uS6wpTSsV9JixgansEXh8ZYeHkg4 = false; // = EnableOfflineKeylogger
    public static bool T5dXaNX16pcyegECMKyP1UJV = true;  // = DebugMode
    public static bool y5TZmU2YQl3cc2zFS = false;    // = CriticalProcess (BSoD on kill)
}
```

The `suvQ4Oayzg()` initializer decrypts all fields, then `PRfiGKKEZAO()` verifies the key's RSA-SHA256 signature against the embedded X509 certificate, ensuring the config was signed by the server operator's private key.

---

## Deep Dive: Opera Process Memory Patching

A technique not documented in the original CAPA analysis. The `Zkijqbq1ZDl8Umj` class (namespace `wibmfaqvvbsngvogkfeetrinzm`) patches Opera's in-memory copy of `GetCursorInfo` in `user32.dll`:

```csharp
// The patch payload: mov eax, 1; ret (always return TRUE)
byte[] patch = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };
```

**Attack flow:**

1. `PatchOperaAsync()` finds all running Opera processes with a main window
2. Adjusts `SeDebugPrivilege` on each target process
3. Locates `user32.dll!GetCursorInfo` in the Opera process's address space by:
   - Loading `user32.dll` locally to get the function's RVA
   - Enumerating the target's modules via `EnumProcessModules` to find `user32.dll`'s remote base
   - Computing the remote address: `remoteBase + (localAddr - localBase)`
4. `VirtualProtectEx` → `PAGE_EXECUTE_READWRITE` on the function prologue
5. `WriteProcessMemory` → overwrites with `mov eax, 1; ret`
6. `ReadProcessMemory` → verifies the patch took
7. Restores original page protection

**Purpose:** Opera uses `GetCursorInfo` as an anti-automation check, if it returns FALSE (no cursor/no user session), Opera refuses certain operations. The patch makes it always return TRUE, enabling the RAT to interact with Opera headlessly for credential extraction and session cloning.

---

## Deep Dive: Windows Recovery Environment Persistence

The most sophisticated persistence mechanism in this sample. The `1OaugIljVER7J5SeXW0HN` class (namespace `fknzwcqedcjvgvtfoeppsxi`) survives full Windows Reset operations:

![Windows RE persistence flow](/assets/images/posts/pulsar/5_winre_persist.png)
*Payload drop → ResetConfig.xml hook injection → batch script generates RunOnce entry → survives full factory reset*

**Attack flow:**

1. Creates `C:\Recovery\OEM\` directory (the Windows RE customization folder)
2. Drops the payload binary with a random 20-char alphanumeric name
3. Generates a batch script that:
   - Reads `HKLM\SOFTWARE\Microsoft\RecoveryEnvironment\TargetOS` to find the OS drive
   - Loads the target OS's `SOFTWARE` registry hive via `reg load`
   - Adds a `RunOnce` entry pointing to the payload
   - Unloads the hive
4. Modifies (or creates) `ResetConfig.xml` to hook two WinRE phases:
   - `BasicReset_AfterImageApply`, fires after "Reset this PC → Keep my files"
   - `FactoryReset_AfterImageApply`, fires after "Reset this PC → Remove everything"
5. If `ResetConfig.xml` already exists, chains the new script after the existing one

**Result:** Even a full factory reset reinstalls the RAT on first boot. This is a rarely-seen technique that significantly raises the cost of remediation, the analyst must manually inspect `C:\Recovery\OEM\` and `ResetConfig.xml`.

---

## Deep Dive: Crypto Clipper (Clipboard Hijacking)

The `WalddVelQIshHagR` class implements clipboard monitoring targeting **9 cryptocurrency address formats**:

```
BTC  — ^(1|3|bc1)[a-zA-Z0-9]{25,39}$
LTC  — ^(L|M|3)[a-zA-Z0-9]{26,33}$
ETH  — ^0x[a-fA-F0-9]{40}$
XMR  — ^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$
SOL  — ^[1-9A-HJ-NP-Za-km-z]{32,44}$
DASH — ^X[1-9A-HJ-NP-Za-km-z]{33}$
XRP  — ^r[0-9a-zA-Z]{24,34}$
TRX  — ^T[1-9A-HJ-NP-Za-km-z]{33}$
BCH  — ^(bitcoincash:)?(q|p)[a-z0-9]{41}$
```

The monitor hooks `WM_CLIPBOARDUPDATE` (message 797) via `AddClipboardFormatListener`. When the clipboard changes, it reads the text on a dedicated STA thread and sends it to C2 via `SetUserClipboardStatus`. The C2 operator can replace addresses with their own via `DoSendAddress`, with anti-echo logic to prevent the replaced address from being re-reported.

---

## Deep Dive: FileHandlerXeno (Locked File Access)

The `FileHandlerXeno` class is a critical enabler for credential theft, it reads files locked by running browsers without killing them:

1. **Normal read**, tries `File.ReadAllBytes()` first
2. **Handle hijacking**, on sharing violation (0x80070020):
   - Calls `NtQuerySystemInformation(SystemExtendedHandleInformation)` to enumerate all open handles system-wide
   - Filters for file handles matching the target path
   - `DuplicateHandle` clones matching handles into the RAT's process
   - `CreateFileMapping` + `MapViewOfFile` reads the file contents through the cloned handle
3. **Process kill fallback**, if handle duplication fails, kills the owning process and retries

This is why the RAT can read Chrome's `Login Data` SQLite database while Chrome is running, without the user noticing any disruption.

---

## C2 Command Dispatch Table

The message handler directory (`xcmobajxobfebgsqbrpftpzbwmcc`) contains 36 classes, each handling specific C2 commands. Complete dispatch map:

| Category | Commands | Handler |
|---|---|---|
| **Client Lifecycle** | `DoClientUninstall`, `DoClientDisconnect`, `DoClientReconnect`, `DoAskElevate`, `DoUACBypass`, `DoClearTempDirectory` | `GbhcNw7dFu` |
| **Remote Desktop** | `GetDesktop`, `DoMouseEvent`, `DoKeyboardEvent`, `DoDrawingEvent`, `GetMonitors`, `DoInstallVirtualMonitor` | `6esDnggERoDgS` |
| **Hidden VNC** | `GetHVNCDesktop`, `DoHVNCInput`, `StartHVNCProcess`, `GetHVNCMonitors` | `qruEd2rLOYNqK8jbD` |
| **Remote Shell** | `DoShellExecute` | `zi6E7tx0f4ok2XbYgxXiq` |
| **Script Exec** | `DoExecScript` (PowerShell, Batch, VBScript, JavaScript) | `HHZ8CTHrqK006` |
| **Process Mgmt** | `GetProcesses`, `DoProcessStart`, `DoProcessEnd`, `DoProcessDump`, `DoSuspendProcess` | `Hjjl7Fmfgzv2jRlSGV` |
| **Credentials** | `GetPasswords` | `wuZQS0fYvXxN` |
| **Browsers** | `GetBrowsers` | `4rbGk1DRFQnDZS` |
| **Keylogger** | `GetKeyloggerLogsDirectory` | `fJT1uBP58o5` |
| **Clipboard** | `DoSendAddress`, `SendClipboardData`, `SetClipboardMonitoringEnabled` | `C0P4pUxY7nCgZX84xueE5cGi` |
| **Webcam** | `GetWebcam`, `GetAvailableWebcams` | `if5GJloLfoL15XFjyiRU` |
| **Microphone** | `GetMicrophone`, `GetMicrophoneDevice` | `gzodkNQZbuCwLvU29qFV7BE` |
| **Speaker** | `GetOutput`, `GetOutputDevice` | `unHySMwyqEmFcyUleQNLOY08xDH` |
| **System Info** | `GetSystemInfo` | `ajX7pNLqQPIvLDCvgJVRZI8F1UF2l` |
| **Persistence** | `GetStartupItems`, `DoStartupItemAdd`, `DoStartupItemRemove` | `1gKwKrvaS8W2Ms2Kx2h6XLNJbsj` |
| **WinRE Persist** | `DoAddWinREPersistence`, `DoRemoveWinREPersistence` | `MGjwxrjlW9ZRWw6BiiGm8KHFBO` |
| **Registry** | `DoLoadRegistryKey`, `DoCreateRegistryKey`, `DoDeleteRegistryKey`, `DoChangeRegistryValue` (+ 4 more) | `thY7EaeYHzLwxbEH` |
| **Network** | `GetConnections`, `DoCloseConnection` | `l3pRgrwMjsnh7eIKv2O6` |
| **Reverse Proxy** | `ReverseProxyConnect`, `ReverseProxyData`, `ReverseProxyDisconnect` | `uRs7xuRFRASbzcQR` |
| **Plugins** | `DoLoadUniversalPlugin`, `DoExecuteUniversalCommand` | `LObq7Q9lUvh1kAzh3XxZD` |
| **Quick Cmds** | `DoSendQuickCommand`, `DoEnableTaskManager`, `DoDisableTaskManager`, `DoDisableUAC`, `DoEnableUAC` | `Ss0FtkI009bDcCD` |
| **Disruption** | `DoBSOD`, `DoSwapMouseButtons`, `DoHideTaskbar`, `DoBlockKeyboardInput`, `DoCDTray`, `DoMonitorsOff` | `KNFVJmTVvrzLqNEJmlIje` |
| **Website** | `DoVisitWebsite` | `A0j9YXq8UrQbZu3D9hsS9kjNNcWIa` |
| **Shutdown** | `DoShutdownAction` | `GaHpzDbaGjcbBdXh5tMscwUfuCW7` |
| **Chat** | `DoChat`, `DoStartChatForm`, `DoKillChatForm` | `iaPtCsb833VBMSr` |
| **Message Box** | `DoShowMessageBox` | `KVuuCHzFHC` |
| **Deferred DLLs** | `DeferredAssembliesPackage` | `ee3zUJMsS3erAdqlc` |

---

## Code Weaknesses and Defensive Opportunities

Despite being significantly more sophisticated than commodity RATs, this Pulsar build has several exploitable flaws visible in the decompiled source.

### The AES Key Is Plaintext. Full Config Decryption From Any Sample

The encryption passphrase for all configuration fields sits in a public static string with no protection:

```csharp
public static string mptvvvwEX9ovort = "F00D8BB24970E7D1F5959C85D7084E366FF0C645";
```

The `Aes256` class in `Pulsar.Common` derives the actual AES-256 key via `SHA256(UTF8(passphrase))`. Given this string, a defender can decrypt every config field. C2 host, port, mutex, install path, campaign tag, from any captured sample without executing it. The key is even sent back to the C2 during the `ClientIdentification` handshake (field `EncryptionKey`), so passive network capture of the first message also reveals it.

The RSA signature verification (`PRfiGKKEZAO()`) that's supposed to protect the config is a single-point-of-failure: it catches all exceptions and returns `false`, and a one-byte IL patch (`brfalse` → `brtrue`) bypasses it entirely.

### The Plugin SHA-256 Check Is Optional. Inject Cleanup DLLs

The deferred assembly loader in `pEdGEk24PvF9Hi` verifies SHA-256 hashes of incoming plugin DLLs, but the check has a critical hole:

```csharp
if (!string.IsNullOrWhiteSpace(descriptor.Sha256) 
    && !text.Equals(descriptor.Sha256, StringComparison.OrdinalIgnoreCase))
{
    return;  // reject mismatched hash
}
// If Sha256 is null or empty → NO CHECK, assembly loaded blindly
```

A C2 impersonator can send a `DeferredAssembliesPackage` with `Sha256 = null` and any .NET assembly they want. It will be loaded via `Assembly.Load(byte[])` with full trust into the current AppDomain, no sandboxing, no code signing. Even better: the assembly gets cached to `%APPDATA%\runtime\modules\` and reloaded automatically on every startup. A defender can drop a cleanup DLL into that directory with local disk access, and it will be loaded on the RAT's next restart.

### The Opera Patcher Only Works on x86. Crashes 64-bit Opera

The `GetCursorInfo` patch payload is hardcoded x86 machine code:

```csharp
byte[] patch = new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };  // mov eax, 1; ret
```

On a 64-bit Opera process, this 6-byte x86 stub is not a valid x64 function prologue. Writing it to the function's entry point will corrupt the instruction stream and likely crash Opera with an access violation. The operator's credential theft pipeline breaks on any 64-bit browser, which is the default on modern Windows. This is a blind spot the developer apparently never tested.

### The Credential Stealer Has a Locale Bug

The Chromium decryptor (`cTFllqAFhI`) converts cipher text through a locale-dependent encoding round-trip:

```csharp
byte[] bytes = Encoding.Default.GetBytes(cipherText);  // ← system locale dependent
```

`Encoding.Default` varies by Windows language. On Japanese, Korean, Chinese, or Arabic systems, this garbles the raw cipher bytes before they reach the AES-GCM decryption path. The credential stealer silently returns empty strings, the operator gets nothing, and they won't know why. This affects Chrome, Brave, Opera, and Opera GX (all Chromium-based). Firefox is unaffected because it uses a separate NSS3 code path.

### Costura Resource Corruption Is a Kill Switch

The Costura `AssemblyLoader` uses a `nullCache` that permanently blacklists any assembly that fails to load:

```csharp
// In ResolveAssembly():
if (nullCache.ContainsKey(name))
    return null;  // never retry
```

If a defender corrupts the `costura.pulsar.common.dll.compressed` embedded resource on disk (even a single byte), the `DeflateStream` decompression throws `InvalidDataException`, the assembly gets null-cached, and the RAT can never load `Pulsar.Common.dll` again, which contains `Aes256`, `MessagePack`, and `SecureMessageEnvelope`. The RAT is permanently bricked. This corruption survives restarts because the null-cache is populated during the module initializer before any recovery logic can run.

### Message Length Has No Upper Bound

The C2 client reads a 4-byte length header and allocates a buffer without checking the size:

```csharp
int num2 = BitConverter.ToInt32(this.headerBuffer, 0);
if (num2 <= 0) throw ...;
// no maximum check — 0x7FFFFFFF (2GB) passes validation
byte[] buffer = new byte[num2];  // ← 2GB allocation attempt
```

A rogue C2 or MITM can send a 4-byte header with `0x7FFFFFFF` to trigger a 2GB allocation, crashing the RAT with `OutOfMemoryException`. Combined with the SecureMessageEnvelope requirement, this is harder to exploit than njRAT's equivalent, but any network position with the X509 public key can craft the payload.

---

## Conclusion

This analysis confirms the sample as Pulsar RAT v2.4.5.0 through Costura manifest strings, preserved namespace identifiers, and async method naming consistent with the public Pulsar source. The C2 protocol uses X509 certificate-based `SecureMessageEnvelope` wrapping over length-prefixed TCP with MessagePack serialization, fully reversible given the embedded certificate and AES passphrase `F00D8BB24970E7D1F5959C85D7084E366FF0C645`. The credential theft pipeline covers all major Chromium-based browsers (Chrome, Brave, Opera, Opera GX) through DPAPI + AES-GCM decryption and Firefox through NSS3 dynamic loading, supported by the `FileHandlerXeno` locked-file reader that bypasses browser file locks via system handle enumeration.

Beyond the upstream QuasarRAT feature set, this build adds several capabilities not present in the public source: **Opera process memory patching** (overwriting `GetCursorInfo` to bypass anti-automation), **Windows Recovery Environment persistence** (surviving full factory reset via `ResetConfig.xml` hook injection), a **9-currency crypto clipper** (BTC, ETH, XMR, SOL, LTC, DASH, XRP, TRX, BCH), **Hidden VNC** with virtual monitor support, **microphone/speaker streaming**, and a **universal plugin loader** for on-demand C2 module delivery with SHA256 verification.

The full deobfuscation of the ConfuserEx-renamed codebase was achieved through four techniques: P/Invoke `EntryPoint` attribute leakage, unobfuscated `Pulsar.Common.*` type references, string literal analysis, and data-flow tracing from known API sinks. The complete C2 command dispatch table maps 26 handler classes covering 60+ individual commands across remote desktop, HVNC, shell execution, credential theft, surveillance, persistence, and system disruption.

**Caveats**: The actual C2 server address requires decrypting the `T1hPcB5PAVrkADQaPu94` field using the AES key, this can be done with the extracted key and the `Pulsar.Common.Cryptography.Aes256` class, or by running `extract_config.py`. The deferred assembly system means additional capabilities (desktop capture, process injection modules) may be delivered at runtime from C2 and are not present in the static binary. DN token offsets and obfuscated field names are specific to this build; other Pulsar variants will differ, though the YARA rules target family-level strings that should persist.

---

*Analysis performed using automated CAPA v9.3.1 / FLOSS pipeline with manual .NET IL cross-reference analysis and decompiled C# source review. All indicators derived from static analysis, no dynamic execution was performed. Obfuscated field mappings are inferred through data-flow tracing from known API sinks.*
