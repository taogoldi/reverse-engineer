---
layout: post
title: "NanoCore RAT v1.2.2.0: Dissecting a Persistent Commercial Trojan"
date: 2026-04-14 00:00:00 +0000
permalink: /blog/nanocore-rat-v1220-analysis/
toc: true
categories: [malware-reversing, threat-intel]
tags: [nanocore, rat, dotnet, mpress, smartassembly, config-extraction, yara, des, aes, pbkdf2]
image:
  path: /assets/images/posts/nanocore/logo.png
  alt: "NanoCore RAT v1.2.2.0 analysis"
---

NanoCore has been lurking in the threat landscape since at least 2013, when its original author sold the builder kit on underground forums for around $25. More than a decade later the tooling keeps reappearing in fresh campaigns, its modular plugin architecture making it easy for operators to bolt on new capabilities without touching the loader. The sample analyzed here -- version 1.2.2.0 -- was compiled on **April 12, 2026** and carries all the hallmarks of the classic NanoCore loader: a SmartAssembly-obfuscated .NET stub, MPRESS packing, and an AES-encrypted Win32 resource containing the live NanoCore DLL.

This post walks through the loader's unpacking chain, the two-stage PBKDF2/AES + DES decryption scheme, full config extraction including live C2 hosts and embedded plugin DLLs, the UAC bypass mechanism, and the binary C2 protocol -- with inline decompiled code, extracted IOCs, and a YARA ruleset at the end.

---

## Sample Properties

| Property | Value |
|---|---|
| **File Name** | `5fa887c8e22c01beb651f843bcb6534b8ab35db986937baaf1f04dbad78ca806.exe` |
| **MD5** | `a196bc59e167c1c5b13da94ae0154ec9` |
| **SHA1** | `ff7bcadd603c90a1a38f803eb38f6515f3e41cf8` |
| **SHA256** | `5fa887c8e22c01beb651f843bcb6534b8ab35db986937baaf1f04dbad78ca806` |
| **Size** | 208,384 bytes |
| **Format** | PE32, .NET CLR (Mono), GUI subsystem |
| **Packer** | MPRESS 2.x |
| **Obfuscator** | SmartAssembly (name mangling + encrypted string table) |
| **Architecture** | x86 (32-bit) |
| **Timestamp** | 0x5553F1A1 (February 14, 2015 -- fabricated, typical for NanoCore) |
| **Assembly Version** | 1.2.2.0 |
| **Assembly GUID** | `7070a103-cc42-421a-8906-6644cd256f9e` |
| **Compiled** | 2026-04-12 05:10:37 UTC |
| **CAPA Risk** | Critical (100/100) |

---

## Kill Chain Overview

![NanoCore Kill Chain](/assets/images/posts/nanocore/killchain.png)

---

## Stage 1: MPRESS Unpacking

The outer shell is packed with MPRESS, a legitimate compression packer whose stub is recognizable by its `MPRESS1` / `MPRESS2` section names. MPRESS stores the original compressed image in one section and a small decompressor stub in another. On execution the stub decompresses the .NET loader into memory and hands control to the CLR entry point (`_CorExeMain`).

After unpacking, three canonical .NET sections are present:

| Section | Virtual Address | Raw Size | Entropy |
|---|---|---|---|
| `.text` | 0x2000 | 116,736 B | 6.60 |
| `.reloc` | 0x20000 | 512 B | 0.10 |
| `.rsrc` | 0x22000 | 90,624 B | **7.998** |

The `.rsrc` section's near-maximum entropy (7.998) is the first indicator that it holds the encrypted NanoCore payload.

---

## Stage 2: SmartAssembly Obfuscation

The unpacked loader is protected by SmartAssembly. Every class, field, and method name is replaced with a Unicode hash identifier following the `#=qXXX=` pattern. String literals are replaced with integer indices into an encrypted string table stored in a managed resource whose name is composed entirely of Unicode zero-width space characters (`\u2009\u2004\u200a\u2002\u2002\u200b\u2007\u2005\u2003\u2008\u2004`).

At runtime the table is decrypted once and cached using a `ThreadStatic` instance. Calls to the decoder look like:

```csharp
// SmartAssembly string decode call
#=qnB6QgyVNIUL$Uq0GD3p5d7LpaFZvHrB3jSqhv3o7qlE=.#=q00kXQ$0a$SV9DIgRtf4NWQ==(516956877)
// returns "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
```

Despite the obfuscation, a handful of strings survive in plaintext because they are referenced by Windows runtime reflection or CLR infrastructure:

```
NanoCore Client
NanoCore Client.exe
NanoCore.ClientPlugin
NanoCore.ClientPluginHost
ClientLoaderForm
RijndaelManaged (in suspicious_strings list)
kernel32.dll, psapi.dll, advapi32.dll, ntdll.dll, dnsapi.dll
```

The presence of `NanoCore.ClientPlugin` and `NanoCore.ClientPluginHost` namespaces immediately identifies the family -- these are the plugin interfaces that all NanoCore modules must implement.

---

## Stage 3: Payload Decryption

The NanoCore DLL is not stored as a second PE inside a ZIP archive. Instead it is AES-128-CBC encrypted inside a Win32 resource (type 10, ID 1, 90,200 bytes). The extraction and decryption logic -- stripped of obfuscation -- looks like this:

```csharp
// 1. Load the Win32 resource via kernel32 API
//    FindResourceEx(hModule: 0, type: 10, id: 1, language: 0)
byte[] resourceBytes = LoadWin32Resource(type: 10, id: 1);

// 2. Parse binary layout with BinaryReader
using var stream = new MemoryStream(resourceBytes);
using var br     = new BinaryReader(stream);

// First block: 16-byte encrypted seed
int    seedLen  = br.ReadInt32();          // always 16 (0x10)
byte[] seedBlob = br.ReadBytes(seedLen);   // a7 52 b0 fc c0 a0 2c 98...

// 3. Decrypt seed using assembly GUID as PBKDF2 key+salt, 8 iterations
Guid assemblyGuid = GetAssemblyGuid(Assembly.GetExecutingAssembly());
// = 7070a103-cc42-421a-8906-6644cd256f9e
byte[] seedDecrypted = AesDecryptBlock(seedBlob, assemblyGuid);
// yields 8 bytes of actual key material + 8 bytes of PKCS7 padding

// 4. Initialize plugin host with decrypted seed (used as inner key material)
pluginHost.LoadAssemblyKey(seedDecrypted);

// 5. Read and decrypt main config/payload block
int    payloadLen  = br.ReadInt32();        // 90,176 bytes
byte[] payloadBlob = br.ReadBytes(payloadLen);
object[] configObjects = pluginHost.DecryptConfig(payloadBlob);
// returns deserialized KV pairs: hosts, mutex, install path, etc.
```

The key derivation function used is PBKDF2-HMAC-SHA1 with the assembly's `[Guid]` attribute value serving as both password and salt, iterated 8 times. The first 16 bytes of output become the AES IV; the next 16 bytes become the AES key.

```csharp
// AES decryption primitive (de-obfuscated)
private static byte[] AesDecryptBlock(byte[] ciphertext, Guid guid)
{
    // guid.ToByteArray() used as BOTH password and salt
    var kdf = new Rfc2898DeriveBytes(
        password:   guid.ToByteArray(),
        salt:       guid.ToByteArray(),
        iterations: 8
    );
    var aes = new RijndaelManaged();
    aes.IV  = kdf.GetBytes(16);   // first  16 bytes = IV
    aes.Key = kdf.GetBytes(16);   // second 16 bytes = Key
    return aes.CreateDecryptor()
              .TransformFinalBlock(ciphertext, 0, ciphertext.Length);
}
```

This design ties the decryption key to the specific compiled binary -- replacing the loader with a recompiled copy would use a different GUID and produce garbage.

---

## Stage 4: Persistence

Before launching the C2 beacon, the loader establishes two persistence vectors:

### HKCU Run Key (user-level)

The binary copies itself to the current user's AppData folder, then writes a registry value under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`:

```csharp
// De-obfuscated persistence logic (HKCU variant)
string installName = config["InstallName"];  // e.g. "WindowsUpdate.exe"
string installDir  = config["InstallFolder"];
string targetPath  = Path.Combine(
    Environment.GetFolderPath(SpecialFolder.ApplicationData),
    installDir,
    installName
);

if (!File.Exists(targetPath))
{
    Directory.CreateDirectory(Path.GetDirectoryName(targetPath));
    File.Copy(Application.ExecutablePath, targetPath);
}

Registry.CurrentUser
    .OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", writable: true)
    .SetValue(config["KeyName"], targetPath);   // registry run key value name from config
```

### HKLM Run Key (admin-level escalation)

If the process has sufficient privileges the same logic repeats under `HKEY_LOCAL_MACHINE`, writing the install copy to `%ProgramFiles%\<installDir>\<installName>` and adding the same run key under HKLM.

### Mutex

A named mutex is created early in execution to prevent multiple instances:

```csharp
new Mutex(initiallyOwned: true, config["Mutex"]);
// Mutex name is config-defined; typical values include random GUIDs
```

---

## Stage 5: C2 Protocol

NanoCore's C2 communication uses a raw TCP socket (no TLS), connecting to the operator-configured hostname and port. DNS resolution is performed via `DnsQuery_A` (from `dnsapi.dll`) when a custom DNS server is specified, falling back to `Dns.GetHostEntry()` otherwise.

The loader distinguishes between LAN targets (RFC 1918 space) and WAN targets for potential routing decisions:

```csharp
// IP classification check (de-obfuscated)
public static bool IsPrivateIP(IPAddress addr)
{
    byte[] b = addr.GetAddressBytes();
    return b[0] == 10 ||
           (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
           (b[0] == 192 && b[1] == 168);
}
```

### Binary Protocol

Commands are dispatched over a persistent TCP connection using a three-layer enum hierarchy:

```csharp
public enum CommandType : byte
{
    BaseCommand   = 0,
    PluginCommand = 1,
    FileCommand   = 2
}

public enum BaseCommand : byte
{
    Initialize,        // 0 -- handshake with build time and key
    ConnectDone,       // 1 -- client ACKs server hello
    CreatePipe,        // 2 -- open a multiplexed data channel
    PipeCreated,       // 3 -- pipe ready confirmation
    Transmission,      // 4 -- generic data transfer
    UnhandledException,// 5 -- client-side exception report
    KeepAlive,         // 6 -- heartbeat
    ExceptionHash,     // 7 -- exception fingerprint
    ExceptionData      // 8 -- exception detail
}

public enum PluginCommand : byte
{
    HostDetails = 0,   // server requests client info
    HostData    = 1,   // client reports system details
    Details     = 2,   // plugin-specific metadata
    Data        = 3    // plugin payload
}

public enum FileCommand : byte
{
    GetDetails    = 0,
    ValidateSource,
    ValidateBlock,
    GetBlockHash,
    WriteBlockData,
    ReadBlockData       // 5 -- chunked file transfer
}
```

The `BaseCommand.Initialize` sequence carries the build timestamp and key material used to authenticate the client to the operator's panel. The `PluginCommand` category is the backbone of NanoCore's modular design -- each plugin registers handlers for `HostDetails`, `Details`, and `Data` messages to expose its capabilities.

### Connection State Machine

The client runs a timer-based reconnect loop. On connection failure, `ConnectionStateChanged` fires, the socket is torn down, and the timer schedules the next attempt with a backoff interval read from the config:

```csharp
// Simplified reconnect handler (de-obfuscated)
private void OnConnectionFailed(object sender, Exception ex)
{
    CloseSocket();
    reconnectTimer.Interval = config["ReconnectDelay"]; // milliseconds
    reconnectTimer.Start();
}
```

---

## Stage 6: Plugin Architecture

What makes NanoCore particularly effective is its plugin-loading mechanism. The loader reflectively loads additional .NET assemblies at runtime by dispatching bytes received over the C2 channel:

```csharp
// Reflective assembly loader (de-obfuscated)
public void LoadPlugin(byte[] assemblyBytes)
{
    Assembly plugin = Assembly.Load(assemblyBytes);
    foreach (Type t in plugin.GetExportedTypes())
    {
        if (typeof(IClientPlugin).IsAssignableFrom(t))
        {
            IClientPlugin instance = (IClientPlugin)Activator.CreateInstance(
                t,
                (IClientDataHost)   this.DataHost,
                (IClientNetworkHost) this.NetworkHost,
                (IClientUIHost)     this.UIHost,
                (IClientLoggingHost) this.LogHost,
                (IClientAppHost)    this.AppHost
            );
            RegisterPlugin(instance);
        }
    }
}
```

Typical plugins distributed with NanoCore builder kits include:
- **SurveillanceEx** -- keylogger, clipboard monitor, webcam/microphone streaming
- **RemoteDesktop** -- VNC-style screen capture
- **FileManager** -- file upload/download/delete
- **NetworkPlugin** -- port scanner, SOCKS proxy
- **RegistryPlugin** -- remote registry browsing

The `FileCommand` enum group drives chunked file transfers supporting resume (via `ValidateBlock` / `GetBlockHash` / `WriteBlockData`), enabling reliable plugin DLL delivery even on unstable connections.

---

## Code Weaknesses

NanoCore's implementation has several exploitable or detectable weaknesses:

1. **Static assembly GUID = static key**: The encryption key for the Win32 resource is derived directly from the assembly's `[Guid]` attribute. Any static PE analysis that reads the GUID attribute can reconstruct the key and decrypt the payload without executing the binary.

2. **Unencrypted namespace strings**: SmartAssembly obfuscates method names but cannot hide .NET type references that the CLR needs for reflection. `NanoCore.ClientPlugin` and `NanoCore.ClientPluginHost` appear verbatim and are definitive signatures.

3. **Plaintext TCP with no certificate pinning**: The C2 channel uses raw TCP binary protocol without TLS. Traffic patterns (fixed port, regular KeepAlive heartbeats, known packet framing) are trivially signaturable in network IDS rules.

4. **Weak PBKDF2 parameters**: 8 iterations of PBKDF2-HMAC-SHA1 is far below modern standards (NIST recommends 600,000+ for HMAC-SHA256). Any analyst who extracts the GUID can brute-force alternative keys in microseconds.

5. **Mutex in plaintext**: The mutex name is embedded in the config, which itself is encrypted. However, if the config is extracted -- via debugging or the static decryption approach above -- the mutex provides a reliable host-based indicator.

---

## Capabilities Summary

| Capability | Evidence |
|---|---|
| **C2 over TCP** | `Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)` |
| **Registry persistence** | `HKCU\...\Run` and `HKLM\...\Run` key writes |
| **File copy / self-replication** | `File.Copy(Application.ExecutablePath, targetPath)` |
| **DNS resolution** | `Dns.GetHostEntry()` + `dnsapi.dll DnsQuery_A` |
| **Process creation** | `ProcessStartInfo` with modified I/O handles |
| **Reflective .NET assembly loading** | `Assembly.Load(bytes)` for plugin delivery |
| **Mutex for single instance** | `new Mutex(true, config["Mutex"])` |
| **System info discovery** | `Environment.MachineName`, OS version, session username, UAC level |
| **AES encryption** | `RijndaelManaged` + PBKDF2 for payload and comms |
| **MD5 hashing** | `ComputeHash` for block-level file transfer validation |
| **Anti-debug** | `Process.EnterDebugMode()`, `IsDebuggerPresent` check |
| **Console allocation** | `AllocConsole` (debug mode only) |
| **Thread suspension** | `Thread.Sleep()` and `Thread.Suspend()` in retry logic |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|---|---|---|
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | HKCU/HKLM `\Run` writes |
| T1620 | Reflective Code Loading | `Assembly.Load(bytes)` plugin delivery |
| T1095 | Non-Application Layer Protocol | Raw TCP binary C2 |
| T1571 | Non-Standard Port | Port configurable in builder (not 80/443) |
| T1082 | System Information Discovery | OS version, hostname, UAC |
| T1033 | System Owner/User Discovery | Session username query |
| T1012 | Query Registry | Multiple HKCU/HKLM reads |
| T1112 | Modify Registry | Run key and config key writes |
| T1083 | File and Directory Discovery | `Directory.EnumerateFiles()` |
| T1005 | Data from Local System | File manager, keylogger, clipboard |
| T1132 | Data Encoding | Binary serialization over TCP |
| T1041 | Exfiltration Over C2 Channel | All data leaves over the C2 socket |
| T1036 | Masquerading | Config-defined install name, copies to AppData |
| T1070.004 | Indicator Removal: File Deletion | Deletes original dropper after install |
| T1106 | Native API | `FindResourceEx`, `LoadResource`, `NtSetInformationProcess`, `GetKernelObjectSecurity` |

---

## Config Extraction

The two-layer decryption chain can be executed statically without running the binary. The key insight from decompiling the plugin host class (`#=qVxXNKnhAcArgJoGGYXiyyQ==`) is that the inner encryption is **DES-CBC** -- not AES as I initially assumed. The seed bytes returned from the AES stage become both the DES key and DES IV.

### Step 1 -- Read the Win32 resource

The config block lives in a Win32 resource (type 10, ID 1). Its binary layout is two length-prefixed blobs:

```python
import pefile, io, struct

pe = pefile.PE('sample.exe')
for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
    if rt.id == 10:  # RT_RCDATA
        for e in rt.directory.entries:
            for d in e.directory.entries:
                res = pe.get_data(d.data.struct.OffsetToData, d.data.struct.Size)

stream    = io.BytesIO(res)
seed_blob = stream.read(struct.unpack('<I', stream.read(4))[0])  # 16 bytes
payload_blob = stream.read(struct.unpack('<I', stream.read(4))[0])  # 90,176 bytes
```

### Step 2 -- Derive the DES key via PBKDF2 + AES

The assembly's `[Guid]` attribute (`7070a103-cc42-421a-8906-6644cd256f9e`) is used as both PBKDF2 password and salt. .NET's `Guid.ToByteArray()` returns the GUID in `bytes_le` (mixed-endian) format, which Python's `uuid.UUID.bytes_le` replicates exactly. The first 16 PBKDF2 output bytes become the AES IV; the next 16 become the AES key. Decrypting the 16-byte seed block and removing PKCS7 padding leaves an 8-byte value -- the DES key.

```python
import uuid
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

assembly_guid = uuid.UUID('7070a103-cc42-421a-8906-6644cd256f9e')
guid_ba = assembly_guid.bytes_le   # matches .NET Guid.ToByteArray()

# PBKDF2-HMAC-SHA1, password = salt = GUID bytes, 8 iterations, 32 bytes output
km = pbkdf2_hmac('sha1', guid_ba, guid_ba, 8, 32)
aes_iv  = km[:16]
aes_key = km[16:]

seed_dec = AES.new(aes_key, AES.MODE_CBC, aes_iv).decrypt(seed_blob)
des_key  = unpad(seed_dec, 16)   # PKCS7 removes 8 padding bytes → 8-byte DES key
# des_key = b'\x72\x20\x18\x78\x8c\x29\x48\x97'
print(f'DES key: {des_key.hex()}')  # 722018788c294897
```

### Step 3 -- Decrypt the payload with DES-CBC

The decompiled `#=qdPDxrK7XRQZlwY8QeW6oe0AEoOr3qND_WVi1o6l48tc=` method initializes a `DESCryptoServiceProvider` with `Key = IV = seed_unpadded`. DES has an 8-byte block size; default .NET mode is CBC with PKCS7 padding.

```python
from Crypto.Cipher import DES

aligned = (len(payload_blob) // 8) * 8
pt = unpad(
    DES.new(des_key, DES.MODE_CBC, des_key).decrypt(payload_blob[:aligned]),
    8
)
```

### Step 4 -- Deflate decompression

The first byte of plaintext is a `bool` indicating compression. For this sample it is `True`, followed by a little-endian `int32` holding the decompressed length, then raw Deflate data (no zlib header -- .NET's `DeflateStream` uses raw deflate):

```python
import zlib

is_compressed = pt[0]  # True
decomp_len    = struct.unpack('<I', pt[1:5])[0]  # 122,751 bytes
pt = zlib.decompress(pt[5:], -15)  # -15 = raw deflate window
assert len(pt) == decomp_len
```

### Step 5 -- Parse the typed binary serialization

After the header (3 bytes: `type_a`, `type_b`, `has_guid`), the stream is a sequence of `(type_tag: byte, value)` pairs. The type map is defined in the static constructor of the plugin host class:

```python
def read_7bit_string(f):
    """BinaryReader.ReadString() -- 7-bit encoded length + UTF-8"""
    result, shift = 0, 0
    while True:
        b = f.read(1)[0]
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return f.read(result).decode('utf-8', errors='replace')

f = io.BytesIO(pt[3:])   # skip type_a, type_b, has_guid
values = []

while f.tell() < len(pt) - 3:
    t = f.read(1)[0]
    if   t == 0:  v = struct.unpack('?', f.read(1))[0]           # bool
    elif t == 1:  v = f.read(1)[0]                                # byte
    elif t == 2:  v = f.read(struct.unpack('<I', f.read(4))[0])  # byte[]
    elif t == 7:  v = struct.unpack('<i', f.read(4))[0]           # int
    elif t == 12: v = read_7bit_string(f)                         # string
    elif t == 15: v = struct.unpack('<H', f.read(2))[0]           # ushort
    elif t == 18: v = uuid.UUID(bytes=f.read(16))                 # Guid
    elif t == 21: v = read_7bit_string(f)                         # Version
    # ... (full type map in scripts/extract_config.py)
    values.append(v)

# Config KV pairs are interleaved: string key, typed value, string key, typed value...
config = {}
i = 0
while i < len(values) - 1:
    if isinstance(values[i], str) and not isinstance(values[i+1], str):
        config[values[i]] = values[i+1]
        i += 2
    else:
        i += 1
```

Running the full extractor (`scripts/extract_config.py`) against the sample produces:

```
$ python3 scripts/extract_config.py sample.exe

NanoCore Config Extraction
============================================================
  _assembly_guid : 7070a103-cc42-421a-8906-6644cd256f9e
  _des_key       : 722018788c294897
  PrimaryConnectionHost   : ama[.]jp[.]net
  BackupConnectionHost    : drmartensoutlet[.]us[.]com
  ConnectionPort          : 443
  Mutex                   : 2762cfe3-bd17-3245-ba92-ed2c5c47a623
  DefaultGroup            : PowerBoost
  Version                 : 1.2.2.0
  BuildTime               : 2026-04-12T05:10:37 UTC
  KeyboardLogging         : True
  RunOnStartup            : True
  RequestElevation        : True
  BypassUserAccountControl: True
  UseCustomDnsServer      : True
  PrimaryDnsServer        : 8.8.8.8
  BackupDnsServer         : 8.8.4.4
  InstallationDialogTitle : PowerBoost
  SurveillanceEx Plugin   : <PE 100352B sha256=01e3b18b...>
  [Embedded PE] NanoCore core DLL  19968B  sha256=61e9d5c0...
  [Embedded PE] SurveillanceEx     100352B sha256=01e3b18b...
```

### Extracted Configuration

| Key | Value |
|---|---|
| **PrimaryConnectionHost** | `ama[.]jp[.]net` |
| **BackupConnectionHost** | `drmartensoutlet[.]us[.]com` |
| **ConnectionPort** | `443` |
| **Mutex** | `2762cfe3-bd17-3245-ba92-ed2c5c47a623` |
| **DefaultGroup** | `PowerBoost` |
| **Version** | `1.2.2.0` |
| **BuildTime** | `2026-04-12 05:10:37 UTC` |
| **KeyboardLogging** | `True` |
| **RunOnStartup** | `True` |
| **RequestElevation** | `True` |
| **BypassUserAccountControl** | `True` |
| **ClearZoneIdentifier** | `True` |
| **ClearAccessControl** | `True` |
| **PreventSystemSleep** | `True` |
| **ActivateAwayMode** | `True` |
| **UseCustomDnsServer** | `True` |
| **PrimaryDnsServer** | `8[.]8[.]8[.]8` |
| **BackupDnsServer** | `8[.]8[.]4[.]4` |
| **ConnectDelay** | `4000 ms` |
| **KeepAliveTimeout** | `30000 ms` |
| **ShowInstallationDialog** | `True` |
| **InstallationDialogTitle** | `PowerBoost` |
| **InstallationDialogMessage** | `Intelligent system optimizer: automatically optimizes CPU, RAM, disk usage and battery life...` |

The lure dialog masquerades as a performance optimizer called "PowerBoost" -- a social engineering wrapper designed to make the victim believe they installed a legitimate tool.

### UAC Bypass

The `BypassUserAccountControlData` field contains an XML Windows Task Scheduler payload used to relaunch the binary at high integrity:

```xml
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>"#EXECUTABLEPATH"</Command>
      <Arguments>$(Arg0)</Arguments>
    </Exec>
  </Actions>
</Task>
```

NanoCore registers this task via the Task Scheduler COM interface, achieving UAC bypass without prompting the user by running at `HighestAvailable` integrity.

### Embedded Plugins

Two PE files are packed inside the config block:

| Index | Description | Size | SHA256 |
|---|---|---|---|
| 2 | NanoCore core client DLL | 19,968 B | `61e9d5c0727665e9ef3f328141397be47c65ed11ab621c644b5bbf1d67138403` |
| 6 | SurveillanceEx plugin DLL | 100,352 B | `01e3b18bd63981decb384f558f0321346c3334bb6e6f97c31c6c95c4ab2fe354` |

The SurveillanceEx plugin implements keylogging (`GetKeyboardLayout`, `GetKeyboardState`), clipboard monitoring (`SetClipboardViewer`, `ChangeClipboardChain`), and window tracking (`GetForegroundWindow`).

---

## IOC Appendix

**File Hashes -- Loader**

| Type | Value |
|---|---|
| MD5 | `a196bc59e167c1c5b13da94ae0154ec9` |
| SHA1 | `ff7bcadd603c90a1a38f803eb38f6515f3e41cf8` |
| SHA256 | `5fa887c8e22c01beb651f843bcb6534b8ab35db986937baaf1f04dbad78ca806` |

**File Hashes -- Embedded DLLs**

| Component | SHA256 |
|---|---|
| NanoCore core DLL | `61e9d5c0727665e9ef3f328141397be47c65ed11ab621c644b5bbf1d67138403` |
| SurveillanceEx plugin | `01e3b18bd63981decb384f558f0321346c3334bb6e6f97c31c6c95c4ab2fe354` |

**Network (defanged)**

| Type | Value |
|---|---|
| Primary C2 | `ama[.]jp[.]net:443` |
| Backup C2 | `drmartensoutlet[.]us[.]com:443` |
| Protocol | Raw TCP binary (no TLS despite port 443) |
| Custom DNS | `8[.]8[.]8[.]8`, `8[.]8[.]4[.]4` |

**Host-based**

| Type | Value |
|---|---|
| Mutex | `2762cfe3-bd17-3245-ba92-ed2c5c47a623` |
| Assembly GUID | `7070a103-cc42-421a-8906-6644cd256f9e` |
| Assembly Version | `1.2.2.0` |
| Build time | `2026-04-12 05:10:37 UTC` |

**Registry Paths**

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<value-from-config>
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<value-from-config>
```

**File System**

```
%APPDATA%\<install-dir>\<install-name>.exe
%ProgramFiles%\<install-dir>\<install-name>.exe
```

---

## YARA Rules

```text
import "pe"
import "dotnet"

rule NanoCore_RAT_Loader_v1_2_2_0
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        date        = "2026-04-14"
        description = "Detects NanoCore RAT v1.2.2.0 loader packed with MPRESS"
        family      = "NanoCore"
        hash_sha256 = "5fa887c8e22c01beb651f843bcb6534b8ab35db986937baaf1f04dbad78ca806"
        reference   = "https://taogoldi.github.io/reverse-engineer/"
        tlp         = "WHITE"

    strings:
        $nc_client      = "NanoCore Client" ascii wide
        $nc_plugin_ns   = "NanoCore.ClientPlugin" ascii wide
        $nc_host_ns     = "NanoCore.ClientPluginHost" ascii wide
        $loader_form    = "ClientLoaderForm" ascii wide
        $rij            = "RijndaelManaged" ascii wide
        $mpress_sig     = { 4D 50 52 45 53 53 }          // "MPRESS"
        $guid_asm       = "7070a103-cc42-421a-8906-6644cd256f9e" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        not pe.characteristics & pe.DLL and
        dotnet.is_dotnet and
        2 of ($nc_client, $nc_plugin_ns, $nc_host_ns, $loader_form) and
        1 of ($rij, $mpress_sig, $guid_asm)
}

rule NanoCore_RAT_SmartAssembly_Obfuscated
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        date        = "2026-04-14"
        description = "Detects NanoCore RAT loader with SmartAssembly obfuscation pattern"
        family      = "NanoCore"
        reference   = "https://taogoldi.github.io/reverse-engineer/"
        tlp         = "WHITE"

    strings:
        // SmartAssembly unicode string table resource name (zero-width Unicode chars)
        $sa_rsrc_name   = { E2 80 A9 E2 80 84 E2 80 8A E2 80 82 E2 80 82 E2 80 8B E2 80 87 E2 80 85 E2 80 83 E2 80 88 E2 80 84 }
        $nc_plugin_if   = "NanoCore.ClientPlugin" ascii wide
        $nc_host_if     = "NanoCore.ClientPluginHost" ascii wide
        $cli_invoke     = "ClientInvokeDelegate" ascii wide
        $rijndael       = "rijndaelmanaged" ascii nocase wide
        $reg_run        = { 53 4F 46 54 57 41 52 45 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 52 75 6E } // SOFTWARE\Microsoft\Windows\CurrentVersion\Run

    condition:
        uint16(0) == 0x5A4D and
        dotnet.is_dotnet and
        pe.number_of_resources >= 1 and
        all of ($nc_plugin_if, $nc_host_if, $cli_invoke) and
        1 of ($sa_rsrc_name, $rijndael, $reg_run)
}

rule NanoCore_RAT_Win32_Resource_Encrypted_Payload
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        date        = "2026-04-14"
        description = "Detects NanoCore RAT loader by its encrypted Win32 Type-10 resource layout"
        family      = "NanoCore"
        reference   = "https://taogoldi.github.io/reverse-engineer/"
        tlp         = "WHITE"
        note        = "Resource starts with 4-byte LE length prefix of 0x10 (=16) followed by an encrypted GUID block"

    strings:
        $nc_client_str  = "NanoCore Client" ascii wide
        $nc_plug_ns     = "NanoCore.ClientPlugin" ascii wide
        $loader_form    = "ClientLoaderForm" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        dotnet.is_dotnet and
        2 of ($nc_client_str, $nc_plug_ns, $loader_form) and
        for any rsrc in pe.resources : (
            rsrc.type == 10 and
            rsrc.length > 50000 and
            rsrc.length < 150000
        )
}
```

---

## Conclusion

NanoCore v1.2.2.0 is a decade-old commercial RAT -- its source leaked publicly around 2014-2016 and it has been analyzed extensively. What makes this particular sample notable is not the codebase itself but the build date: **the PE was compiled on 2026-04-12**, two days before this post, and its C2 infrastructure (`ama[.]jp[.]net`, `drmartensoutlet[.]us[.]com`) does not appear in any public threat intel feed as of writing. This is actively deployed tooling, not a museum artifact.

The obfuscation stack -- MPRESS packing, SmartAssembly name mangling, GUID-keyed AES, and a DES second pass -- is unchanged from publicly documented builds. The "PowerBoost" lure and the specific GUID `7070a103-cc42-421a-8906-6644cd256f9e` are unique to this campaign. The operator is reusing a well-understood tool against targets who have no reason to expect it in 2026, which is the point.

For defenders, the detection surface is rich. The `NanoCore.ClientPlugin` and `NanoCore.ClientPluginHost` namespace strings are invariant across versions. The raw TCP C2 pattern with binary-serialized commands and a predictable KeepAlive heartbeat is straightforward to signature in a network monitor. And the GUID-derived AES key, while clever in concept, is a static artifact readable from any copy of the PE.

---

*Analysis performed on an offline malware research workstation. No network connections were made to potential C2 infrastructure.*
