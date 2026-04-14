---
title: "Dissecting a Chaos/Ares Go Botnet: 12 DDoS Vectors, DNS C2, and 11 Linux Persistence Mechanisms"
permalink: /blog/chaos-ares-go-botnet/
date: 2026-04-13 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [chaos, kaiji, ares, botnet, ddos, golang, linux, elf, persistence, socks5, dns-c2, yara]
image:
  path: /assets/images/social/chaos-ares-2026.jpg
description: "Static analysis of a 2MB Go-compiled Linux DDoS botnet from the Chaos/Kaiji family, Ares variant. 12 attack vectors, DNS-based C2 with AES/DES encryption, SOCKS5 proxy, reverse shell, and 11 persistence mechanisms including SELinux policy bypass."
---

A 2MB statically-linked ELF binary with a generic filename -- `linux_amd64` -- landed in the triage queue with a capa score of 61 and 13 capability findings. No family tag. No sandbox report. Just a stripped Go binary with crypto signals and anti-analysis markers.

GoReSym cracked it open in seconds. The pclntab revealed 23 source files from `C:/src/client/linux/` -- a Windows developer cross-compiling Linux malware with Go 1.20. The function names told the story: `Ares_Plain_Udp`, `Ares_L3_Raw`, `Ares_ipspoof`, `Ares_Tcp_Keep`, `chaos_readfromreader`, `Killcpu`, `Socks5Connect`, `terminalrun`. This is a DDoS botnet with a full attack toolkit, reverse shell, SOCKS5 proxy, and enough persistence mechanisms to survive a system reformat.

The Chaos/Kaiji botnet family has been documented by [Lumen Black Lotus Labs](https://blog.lumen.com/chaos-is-a-go-based-swiss-army-knife-of-malware/) since 2022, with the Ares hacking group operating 13+ C2 panels as recently as 2023. This variant builds on that lineage with 12 distinct DDoS attack vectors, DNS-based C2 with AES/DES encryption, and a persistence engine that touches systemd, SysV init, crontab, shell login scripts, and SELinux policy -- all in a single statically-linked binary.

---

## The Sample

| Property | Value |
|---|---|
| **SHA-256** | `a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd` |
| **MD5** | `0df954759bd65fe0c257a084c` |
| **Size** | 2,011,136 bytes (1.9 MB) |
| **Format** | ELF 64-bit LSB executable, x86-64, statically linked |
| **Language** | Go 1.20 (`-ldflags "-s -w"`, `CGO_ENABLED=0`) |
| **Build Env** | Windows (`C:/Program Files/Go/`, `C:/src/client/linux/`) |
| **Functions** | 166 custom (main package) + 2,248 stdlib |
| **Source Files** | 23 (recovered from Go pclntab) |
| **Build ID** | `9f3aGTNZ1NqDQgjyl7Bs/QGy4ge3vDxRLRpuKggby/KTQeE9n5NZZsIG16ifyG/7KQSl1XiJmykz3-kickd` |

The binary is stripped (`-s -w` ldflags remove symbol table and DWARF debug info) and statically linked (no external dependencies). Cross-compiled on Windows for Linux -- the Go SDK path `C:/Program Files/Go/` and the source tree at `C:/src/client/linux/` confirm the developer works on Windows.

### Online Attribution

VirusTotal detection stands at 21/66 with the popular threat label **trojan.kaiji/ares**. Multiple sandbox platforms confirm the classification:

| Platform | Verdict | Score | C2 Extracted |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com/gui/file/a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd) | trojan.kaiji/ares | 21/66 | -- |
| [Joe Sandbox](https://www.joesandbox.com/analysis/1896921/0/html) | MAL (Kaiji) | 84/100 | `s4[.]quicklyspeed[.]com`, `183[.]236[.]97[.]73`, `176[.]65[.]149[.]237` |
| [Hatching Triage](https://tria.ge/260411-wz42vaex7k) | Kaiji | 10/10 | `s4[.]quicklyspeed[.]com:8080` |
| [Intezer](https://analyze.intezer.com/analyses/ca4b2ca6-7f4f-4efa-aef4-f18fd6830809) | Kaiji | -- | -- |
| [MalwareBazaar](https://bazaar.abuse.ch/sample/a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd) | Kaiji | -- | -- |
| [Nucleon](https://malprob.io/report/a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd) | MALWARE | 100% | -- |
| [threat.rip](https://www.threat.rip/file/a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd) | Family.KAIJI | 100/100 | -- |

The C2 domain `s4[.]quicklyspeed[.]com` on port 8080 was extracted by Joe Sandbox and Hatching Triage during dynamic analysis. The IP `183[.]236[.]97[.]73` resolves to China Telecom infrastructure, consistent with the Chaos/Kaiji family's documented Chinese origin.

Florian Roth's THOR APT Scanner matched `SUSP_CronTab_Entries_Sep24_2`, confirming the crontab persistence technique. The VT community also identified four generic Linux threat YARA rules from petikvx matching the binary.

MCRIT code similarity analysis from our threat intel platform found a **Windows PE variant** (`ee0b9fbd...`, first seen 2026-04-02) sharing **578 functions** with this Linux sample -- both compiled with Go 1.20 from the same source tree. This confirms the cross-platform nature of the Ares toolkit: one codebase, compiled for both `GOOS=linux` and `GOOS=windows`.

---

## Kill Chain

![Kill chain](/assets/images/posts/chaos_ares/1_killchain.png)
*Chaos/Ares bot connects to DNS-based C2, receives commands via custom chaos protocol, dispatches to 12 DDoS vectors, reverse shell, SOCKS5 proxy, CPU killer, or persistence engine.*

---

## Source File Recovery

GoReSym extracted the complete source tree from the Go pclntab. Even though the binary is stripped, Go's runtime metadata preserves file paths and function names:

```text
C:/src/client/linux/main.go          -- Entry point, main loop
C:/src/client/linux/client.go        -- C2 client connection handler
C:/src/client/linux/protocol.go      -- Custom chaos wire protocol
C:/src/client/linux/attack.go        -- DDoS attack dispatcher (3,296 bytes)
C:/src/client/linux/ares_plan_udp.go -- UDP flood planner
C:/src/client/linux/ares_raw.go      -- Raw socket flood
C:/src/client/linux/ares_spoof.go    -- IP spoofing attack
C:/src/client/linux/ares_tcp.go      -- TCP flood
C:/src/client/linux/ares_tcp_keep.go -- TCP keepalive flood
C:/src/client/linux/ares_udp.go      -- UDP flood
C:/src/client/linux/aes.go           -- AES encryption (CFB/CBC/ECB)
C:/src/client/linux/socks5.go        -- SOCKS5 proxy server
C:/src/client/linux/terminal.go      -- Reverse shell handler
C:/src/client/linux/killcpu.go       -- CPU exhaustion
C:/src/client/linux/watchdog.go      -- Self-monitoring / restart
C:/src/client/linux/onlineinfo.go    -- System fingerprinting
C:/src/client/linux/ini.go           -- Configuration parser
C:/src/client/linux/init.go          -- Persistence installer
C:/src/client/linux/old.go           -- Legacy compatibility
C:/src/client/linux/getrand.go       -- Random number generation
C:/src/client/linux/strtohex.go      -- Hex encoding
C:/src/client/linux/tool.go          -- Utility functions
C:/src/client/linux/type.go          -- Type definitions
```

The developer organized the code cleanly. Each attack vector gets its own file. The naming convention uses `ares_` prefix for the DDoS modules and descriptive names for everything else. This is not a script kiddie project -- it is a modular, maintained codebase.

### Source Code Projection (redress)

Using [redress](https://github.com/goretk/redress), we can recover the original source line counts for every function. This gives us a code complexity map of the entire bot:

```text
File: attack.go        -- 78 lines, 13 sub-functions (command dispatcher)
File: client.go        -- 232 lines (handle: 136 lines, 8 sub-handlers)
File: init.go          -- 297 lines (inits: 116 lines persistence installer)
File: ares_spoof.go    -- 110 lines (Ares_ipspoof: 103 lines raw packet forge)
File: ares_udp.go      -- 352 lines (Ares_L3_Udp: 141 + Ares_L3_Udp_Hex: 164)
File: ares_tcp_keep.go -- 139 lines (6 attack functions + helpers)
File: ares_tcp.go      -- 99 lines (Ares_Tcp + Ares_Tcp_Hex)
File: ares_raw.go      -- 178 lines (Raw: 13 + Ares_L3_Raw: 152)
File: ares_plan_udp.go -- 91 lines (Udpplain + Ares_Plain_Udp variants)
File: protocol.go      -- 132 lines (chaos_readfromreader + chaos_checkMsg + Ares_send)
File: socks5.go        -- 156 lines (SOCKS5 proxy + auth + connect)
File: terminal.go      -- 77 lines (reverse shell + I/O handlers)
File: killcpu.go       -- 143 lines (CPU kill + PID enumeration + process kill)
File: aes.go           -- 91 lines (Dns_Url/Key + DecryptCFB/CBC/ECB + DesDecrypt)
File: old.go           -- 134 lines (win/windec/web/webdec config handlers)
File: main.go          -- 105 lines (entry + main loop)
File: ini.go           -- 89 lines (config parser)
File: watchdog.go      -- 40 lines (self-monitor + restart)
File: onlineinfo.go    -- 49 lines (system fingerprint)
File: type.go          -- 164 lines (Allowlist + Enc/Dec + GetTag)
File: tool.go          -- 124 lines (file ops + Shell + IP conversion)
```

The largest module by line count is `ares_udp.go` (352 lines) -- the Layer 3 UDP flood with full IP header construction. The most complex control flow is in `client.go` `handle()` (136 lines, 8 nested handler closures) which is the C2 command dispatcher.

### The Command Dispatcher (client.go)

The `handle()` function (136 lines) is the brain of the bot. Redress shows it contains 8 sub-handler closures (`handle.func1` through `handle.func1.8`), each mapped to a C2 command. The dispatcher receives messages via `chaos_checkMsg`, parses the command byte, and routes to the appropriate handler:

```text
handle()                 -- Main dispatch loop (136 lines)
  handle.func1           -- Primary command router (105 lines)
    handle.func1.1       -- Handler 1: attack command
    handle.func1.2       -- Handler 2: terminal/shell
    handle.func1.3       -- Handler 3: proxy control
    handle.func1.4       -- Handler 4: file operations
    handle.func1.5       -- Handler 5: persistence/update
    handle.func1.6       -- Handler 6: kill/stop
    handle.func1.7       -- Handler 7: allowlist management
    handle.func1.8       -- Handler 8: system info/config
```

This nested closure pattern is idiomatic Go. Each handler is a goroutine-safe closure that captures the connection context from the parent `handle()` scope.

### The IP Spoofing Attack (ares_spoof.go)

`Ares_ipspoof` at 103 lines is one of the most interesting functions. It constructs raw IP packets with forged source addresses, requiring `CAP_NET_RAW` capability or root access on the compromised host. The attack flow:

```text
Ares_ipspoof (103 lines):
  1. Parse target IP and port from C2 command
  2. Open raw socket (AF_INET, SOCK_RAW, IPPROTO_RAW)
  3. Set IP_HDRINCL socket option (tells kernel we provide the full IP header)
  4. Loop for attack duration:
     a. Generate random source IP from allowed ranges
     b. Construct IP header (version, IHL, total length, TTL, protocol)
     c. Compute IP header checksum
     d. Construct TCP/UDP header with forged source
     e. Send raw packet via sendto()
```

This is a volumetric reflection/amplification enabler. With spoofed source IPs, the attacker can direct response traffic from third-party services (DNS resolvers, NTP servers, memcached) toward the victim, multiplying the attack bandwidth.

### The Persistence Installer (init.go)

`inits()` at 116 lines deploys 11 persistence mechanisms in sequence. Redress shows the full init.go structure:

```text
init.go (297 lines total):
  Killsh (19 lines)          -- Kill competing processes first
  kpid (17 lines)            -- Kill by PID helper
  inits (116 lines)          -- Main persistence installer
  rclocal (54 lines)         -- Modify /etc/rc.d/rc.local
  initsh (17 lines)          -- Write init.d script
  initshread (32 lines)      -- Read/modify init scripts
  readtime (7 lines)         -- Check file modification time
  replace (5 lines)          -- String replacement helper
  replacea (5 lines)         -- String replacement variant
  replacesh (9 lines)        -- Shell script replacement
```

The `inits()` function first calls `Killsh` to eliminate competing bots, then sequentially deploys each persistence mechanism. The `rclocal` function alone is 54 lines, handling the detection and modification of `/etc/rc.d/rc.local` across different Linux distributions (RHEL/CentOS use `/etc/rc.d/rc.local`, Debian/Ubuntu use `/etc/rc.local`).

---

## C2 Protocol: DNS-Based with Encrypted Key Exchange

The bot uses DNS queries for both C2 resolution and encryption key exchange, handled by two dedicated functions:

```text
main.Dns_Url    @ 0x60d2a0  (384 bytes)  -- Resolve C2 URL via DNS
main.Dns_Key    @ 0x60d420  (384 bytes)  -- Exchange encryption key via DNS
main.connect    @ 0x617560  (416 bytes)  -- Establish C2 connection
main.Link       @ 0x6173e0  (288 bytes)  -- Maintain C2 link
main.handle     @ 0x615b80  (832 bytes)  -- Command dispatcher
main.socket     @ 0x615900  (544 bytes)  -- Socket management
```

The `Dns_Url` function resolves the C2 server address through DNS, which lets the operator rotate infrastructure by updating DNS records without recompiling the bot. `Dns_Key` performs an encryption key exchange over DNS -- the bot sends a query and receives the AES/DES key material in the DNS response. This is a well-known C2 evasion technique: DNS queries blend into normal traffic, and most network monitoring tools don't inspect DNS TXT record payloads.

The custom protocol uses a `chaos_*` function family for message handling:

```text
main.(*Buffer).chaos_readfromreader  -- Read messages from C2 socket
main.(*Buffer).chaos_checkMsg        -- Validate message integrity
main.(*Buffer).chaos_grow            -- Grow message buffer
main.Ares_send                       -- Send response to C2
```

The `chaos_checkMsg` function validates incoming commands before dispatch, and `Ares_send` returns attack results and bot status to the operator.

### Encryption Stack

Five decryption functions handle C2 traffic and config protection:

```text
main.DecryptCFB  @ 0x60d5a0  (320 bytes)  -- AES-CFB mode
main.DecryptCBC  @ 0x60d6e0  (384 bytes)  -- AES-CBC mode
main.DecryptECB  @ 0x60d860  (768 bytes)  -- AES-ECB mode
main.DesDecrypt  @ 0x60db60  (352 bytes)  -- DES decryption
main.Enc         @ 0x620720  (416 bytes)  -- Generic encryption
main.Dec         @ 0x6208c0  (544 bytes)  -- Generic decryption
```

The presence of three AES modes (CFB, CBC, ECB) plus DES suggests different encryption is used for different communication phases -- likely DES for the initial handshake and AES for bulk data transfer.

Additionally, two config decryption functions handle obfuscated configuration:

```text
main.windec  @ 0x61bf60  (512 bytes)  -- Decrypt config variant 1
main.webdec  @ 0x61c5a0  (512 bytes)  -- Decrypt config variant 2
```

---

## The Attack Engine: 12 DDoS Vectors

The `attack()` function at `0x614680` (3,296 bytes) is the central command dispatcher. It receives attack parameters from the C2 and routes to 13 sub-functions, each implementing a different DDoS technique:

![Attack vectors](/assets/images/posts/chaos_ares/2_attack_vectors.png)
*12 DDoS attack vectors across UDP, TCP, and raw socket categories. Each has a plaintext and hex-encoded payload variant.*

### UDP Attacks

```text
main.Ares_Plain_Udp      @ 0x60e2a0  (704 bytes)  -- UDP flood, plaintext payload
main.Ares_Plain_Udp_Hex  @ 0x60e5c0  (608 bytes)  -- UDP flood, hex-encoded payload
main.Ares_L3_Udp         @ 0x6129e0  (3,360 bytes) -- Layer 3 UDP (raw socket, crafted headers)
main.Ares_L3_Udp_Hex     @ 0x613760  (3,776 bytes) -- Layer 3 UDP, hex payload
```

The L3 UDP functions (`Ares_L3_Udp`, 3,360 bytes) are significantly larger than the plain UDP functions (704 bytes) because they construct raw IP/UDP headers manually rather than using Go's `net.Dial`. This gives the attacker control over source IP spoofing and packet fragmentation.

### TCP Attacks

```text
main.Ares_Tcp            @ 0x610700  (544 bytes)   -- TCP SYN flood
main.Ares_Tcp_Hex        @ 0x610920  (640 bytes)   -- TCP flood, hex payload
main.Ares_Tcp_Keep       @ 0x611440  (448 bytes)   -- TCP keepalive flood (hold connections open)
main.Ares_Tcp_Keep_Hex   @ 0x611a20  (448 bytes)   -- TCP keepalive, hex payload
main.Ares_Tcp_Send       @ 0x6116c0  (576 bytes)   -- TCP data send flood
main.Ares_Tcp_Read       @ 0x611960  (192 bytes)   -- TCP read-based attack
```

The TCP keepalive flood (`Ares_Tcp_Keep`) is designed to exhaust connection tables on the target. Instead of sending and closing (like a SYN flood), it opens connections and holds them open with keepalive packets, consuming server resources until the connection limit is reached.

### Raw Socket and IP Spoofing

```text
main.Ares_L3_Raw   @ 0x60eda0  (2,304 bytes)  -- Raw socket flood (L3)
main.Ares_ipspoof  @ 0x60f700  (1,792 bytes)  -- IP spoofing attack
```

`Ares_ipspoof` (1,792 bytes) uses Linux raw sockets with `IP_HDRINCL` to craft packets with forged source IP addresses. This makes DDoS traffic harder to filter because every packet appears to come from a different source. It also enables reflection/amplification attacks where the target receives response traffic from third-party services.

### Attack Helpers

Each attack category has helper functions for concurrent execution:

```text
main.Udpplain      @ 0x60dcc0  (1,216 bytes)  -- UDP worker goroutine
main.Raw           @ 0x60e880  (1,088 bytes)  -- Raw socket worker
main.Tcp           @ 0x60fe60  (896 bytes)    -- TCP worker
main.Tcpkeep       @ 0x610ba0  (896 bytes)    -- TCP keepalive worker
main.Udp           @ 0x611fe0  (1,056 bytes)  -- Generic UDP worker
main.timeover      @ 0x615840  (192 bytes)    -- Attack duration timer
```

The `timeover` function enforces attack duration limits -- the C2 specifies how long each attack should run, and `timeover` kills the goroutines when the timer expires.

---

## Remote Access: Shell and SOCKS5 Proxy

### Reverse Shell

```text
main.terminalrun    @ 0x61e620  (1,184 bytes)  -- Start reverse shell
main.terminalwriter @ 0x61eea0  (224 bytes)    -- Write to shell stdin
main.terminalclose  @ 0x61ee20  (128 bytes)    -- Close shell session
main.Shell          @ 0x61fb40  (160 bytes)    -- Execute /bin/sh
```

The `terminalrun` function (1,184 bytes) spawns `/bin/sh` and connects its stdin/stdout to the C2 socket. This gives the operator a full interactive shell on the compromised machine. The `terminalwriter` function handles input from the operator, and three nested closures (`terminalrun.func1`, `.func2`, `.func3`) manage goroutines for concurrent I/O.

### SOCKS5 Proxy

```text
main.StartProxy    @ 0x61d220  (192 bytes)   -- Start SOCKS5 server
main.CloseProxy    @ 0x61d2e0  (96 bytes)    -- Stop SOCKS5 server
main.(*Proxy).Run  @ 0x61d340  (320 bytes)   -- Accept connections
main.Proxyhandle   @ 0x61d4e0  (608 bytes)   -- Handle proxy traffic
main.Socks5Auth    @ 0x61d860  (704 bytes)   -- SOCKS5 authentication
main.Socks5Connect @ 0x61db20  (2,112 bytes) -- SOCKS5 CONNECT handler
```

The SOCKS5 proxy turns the bot into a traffic relay. The operator can route arbitrary TCP connections through the compromised machine, which is useful for:
- Anonymizing the operator's real IP during attacks
- Pivoting into internal networks behind the compromised host
- Selling proxy access as a service (residential proxy networks)

`Socks5Connect` at 2,112 bytes is one of the largest functions in the binary, handling the full SOCKS5 CONNECT handshake including DNS resolution, authentication, and bidirectional data relay.

---

## Resource Abuse

```text
main.Killcpu         @ 0x61a840  (320 bytes)   -- CPU exhaustion
main.Killsh          @ 0x6181a0  (352 bytes)   -- Kill competing processes
main.kpid            @ 0x618300  (512 bytes)   -- Kill by PID
main.readPidsFromDir @ 0x61a980  (416 bytes)   -- Enumerate /proc PIDs
```

`Killcpu` is a cryptomining defense: it spins CPU cores to 100% usage, making the machine unusable. This can be used as a denial-of-service against the host itself, or to disrupt competing malware (other bots mining crypto on the same machine).

`Killsh` and `kpid` actively hunt and kill competing processes. The binary references analysis tools (`netstat`, `lsof`, `ps`, `ss`, `find`) -- these are likely monitored and their processes killed when detected.

---

## Persistence: 11 Mechanisms

The `inits()` function at `0x618560` (4,320 bytes) is the persistence installer. It deploys 11 different survival mechanisms across every major Linux init system:

![Persistence mechanisms](/assets/images/posts/chaos_ares/3_persistence.png)
*11 persistence mechanisms spanning systemd, SysV init, shell login scripts, crontab, and SELinux policy bypass.*

### systemd Service

The bot creates a fake `quotaoff.service` that masquerades as a disk quota management service:

```text
ExecStart=/boot/System.mod
ExecReload=/boot/System.mod
ExecStop=/boot/System.mod
```

The service file is written to `/usr/lib/systemd/system/quotaoff.service` and enabled via `systemctl enable`. The binary itself is copied to `/boot/System.mod`, blending in with legitimate boot files.

### SysV Init

```text
/etc/rc.d/rc.local       -- Appended to boot script
/etc/init.d/boot.local   -- Init script
chkconfig: 2345 10 90    -- Enabled in runlevels 2-5, priority 10
```

The `chkconfig` header ensures the init script starts early (priority 10) and across all multiuser runlevels (2-5). The `rclocal()` function at `0x619640` (1,856 bytes) handles rc.local modification.

### Shell Login Persistence

```text
/etc/profile.d/bash_cfg.sh   -- Executed on every bash login
/etc/profile.d/gateway.sh    -- Executed on every bash login
```

Dropping scripts in `/etc/profile.d/` ensures the bot relaunches whenever any user opens a shell session. This survives reboots and is rarely checked by administrators.

### Crontab

```text
echo "*/1 * * * * root /.mod " >> /etc/crontab
```

The bot adds a crontab entry that runs `/.mod` (a copy of itself) every minute as root. Even if all other persistence is cleaned, the crontab entry relaunches the bot within 60 seconds.

### SELinux Policy Bypass

This is the most sophisticated persistence technique in the binary:

```text
cd /boot; ausearch -c 'System.mod' --raw | audit2allow -M my-Systemmod;
semodule -X 300 -i my-Systemmod.pp
```

The bot uses `ausearch` to find SELinux audit denials for `System.mod`, pipes them through `audit2allow` to auto-generate a permissive policy module, then installs it with `semodule` at priority 300. This effectively tells SELinux to allow everything the bot does. On systems where SELinux is enforcing, this is the difference between the bot working and being killed.

### Marker File

```text
/lib/system-mark    -- Installation marker/lockfile
```

The marker file prevents double-installation. The `inits()` function checks for this file before running the persistence installer.

---

## IP Allowlist

```text
main.(*Allowlist).Add     @ 0x61fd40  (672 bytes)  -- Add IP to allowlist
main.(*Allowlist).Del     @ 0x620040  (928 bytes)  -- Remove IP from allowlist
main.(*Allowlist).Delall  @ 0x620440  (192 bytes)  -- Clear allowlist
main.(*Allowlist).Is      @ 0x620560  (352 bytes)  -- Check if IP is allowed
```

The allowlist is a DDoS targeting control. The operator can specify IPs that should never be attacked -- likely their own infrastructure, paying customers, or allied botnets. The `Is()` function is called before every attack to skip allowlisted targets.

---

## System Fingerprinting

```text
main.Onlineinfo  @ 0x61c7c0  (896 bytes)  -- Collect system info
main.GetTag      @ 0x61fbe0  (352 bytes)  -- Get campaign/group tag
```

`Onlineinfo` collects the bot's system profile and reports it to the C2. This likely includes hostname, kernel version, CPU count, memory, and network interfaces -- everything the operator needs to assess the bot's attack capacity.

---

## Code Weaknesses

1. **Source paths leaked in pclntab**: Despite stripping with `-s -w`, Go's pclntab preserves file paths (`C:/src/client/linux/*.go`). This reveals the developer uses Windows, the source directory structure, and every module name. A single GoReSym run exposes the entire codebase architecture.

2. **Function names preserved**: All 166 custom function names survive stripping. `Ares_Plain_Udp`, `Killcpu`, `Socks5Connect` -- every capability is labeled in plaintext. This makes YARA detection trivial: matching 3 function name strings identifies the family with near-zero false positives.

3. **Hardcoded persistence paths**: All 11 persistence paths (`/boot/System.mod`, `/lib/system-mark`, `/usr/lib/systemd/system/quotaoff.service`, etc.) are compiled into the binary as string literals. A defender can create inotify watches on these paths for instant detection.

4. **Static binary with no obfuscation**: The binary is 2MB of unobfuscated Go. No garble, no UPX, no custom packer. Every string, every function name, every file path is readable with a basic `strings` command.

5. **SELinux bypass is auditable**: The `ausearch + audit2allow + semodule` chain leaves an audit trail in `/var/log/audit/audit.log`. The custom policy module `my-Systemmod.pp` is visible in `semodule -l` output. This persistence mechanism is sophisticated but not stealthy.

6. **Crontab entry is trivially detectable**: `*/1 * * * * root /.mod` in `/etc/crontab` runs as root every minute with a hidden filename. Any crontab monitoring tool (osquery, auditd, AIDE) flags this immediately.

7. **Cross-compilation fingerprint**: Building on Windows (`C:/Program Files/Go/`) for Linux creates a distinctive forensic signature. The Go build path in pclntab is a reliable indicator that the binary was not built on the target platform.

8. **No DNS query encryption**: While the C2 uses DNS for resolution and key exchange, standard DNS queries are plaintext. Any network monitor logging DNS TXT queries will capture the C2 communication. DNS-over-HTTPS or DNS-over-TLS would have been harder to detect.

9. **Single-binary, multi-function design**: Combining DDoS, reverse shell, SOCKS proxy, and persistence in one binary means a single YARA rule or hash block stops all capabilities simultaneously. A modular design with separate components would be more resilient to partial detection.

---

## IOC Appendix

### Network Indicators

| Type | Value | Context |
|---|---|---|
| Domain | `s4[.]quicklyspeed[.]com` | Primary C2 server (port 8080) |
| Port | `8080/tcp` | C2 port |
| IP | `183[.]236[.]97[.]73` | C2 infrastructure (China Telecom) |
| IP | `176[.]65[.]149[.]237` | C2 infrastructure |

### Host Indicators

| Type | Value | Context |
|---|---|---|
| File | `/boot/System.mod` | Bot binary masquerading as boot module |
| File | `/.mod` | Crontab-executed copy |
| File | `/lib/system-mark` | Installation marker |
| File | `/usr/sbin/ifconfig.cfg` | Config storage |
| Service | `/usr/lib/systemd/system/quotaoff.service` | Fake systemd service |
| Script | `/etc/profile.d/bash_cfg.sh` | Login persistence |
| Script | `/etc/profile.d/gateway.sh` | Login persistence |
| Script | `/etc/rc.d/rc.local` (modified) | Boot persistence |
| Crontab | `*/1 * * * * root /.mod` | Minute-interval persistence |
| SELinux | `my-Systemmod.pp` policy module | SELinux bypass |

### File Hashes

| Artifact | SHA-256 |
|---|---|
| Bot binary (Linux ELF) | `a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd` |
| Windows variant (MCRIT match, 578 shared functions) | `ee0b9fbdcfcf4fed1f2e960539b06e76cdc600240596b186f24561028691c34e` |

### MITRE ATT&CK Mapping

| ID | Technique | Evidence |
|---|---|---|
| T1498.001 | Direct Network Flood | 12 DDoS attack vectors (UDP/TCP/Raw/Spoof) |
| T1090.001 | Internal Proxy | SOCKS5 proxy server |
| T1059.004 | Unix Shell | Reverse shell via `/bin/sh` |
| T1053.003 | Cron | `*/1 * * * * root /.mod` |
| T1543.002 | Systemd Service | `quotaoff.service` |
| T1037.004 | RC Scripts | `/etc/rc.d/rc.local` modification |
| T1546.004 | Unix Shell Config | `/etc/profile.d/bash_cfg.sh` and `gateway.sh` |
| T1562.001 | Disable Security Tools | SELinux policy bypass via `audit2allow` |
| T1496 | Resource Hijacking | `Killcpu` CPU exhaustion |
| T1027.002 | Software Packing | Stripped Go binary (`-s -w` ldflags) |
| T1140 | Deobfuscate/Decode | AES-CFB/CBC/ECB + DES decryption for config/C2 |
| T1071.004 | DNS | `Dns_Url` and `Dns_Key` DNS-based C2 resolution |
| T1071.001 | Web Protocols | C2 at `s4[.]quicklyspeed[.]com:8080` |
| T1057 | Process Discovery | `readPidsFromDir` enumerates `/proc` |
| T1489 | Service Stop | `Killsh` kills competing processes |

---

## Detection

### YARA Rules

Three rules. Full file: [`botnets/chaos/chaos_ares_botnet.yar`](https://github.com/taogoldi/YARA/blob/main/botnets/chaos/chaos_ares_botnet.yar)

```text
import "elf"

rule Chaos_Ares_DDoS_Botnet {
    meta:
        description = "Detects Chaos/Kaiji botnet Ares variant with DDoS + DNS C2"
        author = "Tao Goldi"
        version = 1
        family = "Chaos/Kaiji"
    strings:
        $ares1 = "Ares_Plain_Udp" ascii
        $ares2 = "Ares_L3_Raw" ascii
        $ares3 = "Ares_ipspoof" ascii
        $ares4 = "Ares_Tcp" ascii
        $ares5 = "Ares_L3_Udp" ascii
        $chaos1 = "chaos_readfromreader" ascii
        $chaos2 = "chaos_checkMsg" ascii
        $dns1 = "Dns_Url" ascii
        $dns2 = "Dns_Key" ascii
    condition:
        elf.machine == elf.EM_X86_64 and
        ((3 of ($ares*)) or ($chaos1 and $chaos2) or
         ($dns1 and $dns2 and 2 of ($ares*)))
}

rule Chaos_Kaiji_Generic {
    meta:
        description = "Generic Chaos/Kaiji Go botnet family detection"
        author = "Tao Goldi"
        version = 1
        family = "Chaos/Kaiji"
    strings:
        $chaos1 = "chaos_readfromreader" ascii
        $chaos2 = "chaos_checkMsg" ascii
        $atk1 = "Ares_Plain_Udp" ascii
        $atk2 = "Ares_L3_Raw" ascii
        $atk3 = "Ares_ipspoof" ascii
        $kill1 = "Killcpu" ascii
        $kill2 = "Killsh" ascii
        $socks = "Socks5Connect" ascii
        $term = "terminalrun" ascii
        $watch = "Watchdog" ascii
    condition:
        filesize < 10MB and
        ((2 of ($chaos*)) or
         (3 of ($atk*) and 1 of ($chaos*)) or
         (1 of ($chaos*) and 1 of ($kill*) and $socks and $term))
}

rule Chaos_Ares_Persistence_Scripts {
    meta:
        description = "Detects Chaos/Ares persistence via init scripts + SELinux bypass"
        author = "Tao Goldi"
        version = 1
        family = "Chaos/Kaiji"
    strings:
        $boot = "/boot/System.mod" ascii
        $systemd = "quotaoff.service" ascii
        $marker = "/lib/system-mark" ascii
        $profile = "/etc/profile.d/bash_cfg" ascii
        $selinux = "audit2allow" ascii
        $chkconfig = "chkconfig: 2345" ascii
    condition:
        filesize < 10MB and
        ((3 of them) or ($selinux and $boot) or ($chkconfig and $boot and $marker))
}
```

### Sigma (Linux Auditd)

```text
title: Chaos/Ares Botnet Persistence Detection
status: experimental
logsource:
    product: linux
    service: auditd
detection:
    selection_files:
        - path|contains:
            - '/boot/System.mod'
            - '/lib/system-mark'
            - '/.mod'
    selection_selinux:
        - comm: 'audit2allow'
        - comm: 'semodule'
    selection_crontab:
        - path: '/etc/crontab'
          type: 'OPENAT'
    condition: 1 of selection_*
level: critical
```

---

## Conclusion

This Chaos/Ares variant is a well-engineered DDoS weapon. 12 attack vectors, DNS-based C2, AES/DES encrypted communications, SOCKS5 proxy for traffic laundering, reverse shell for hands-on-keyboard access, and 11 persistence mechanisms that cover every Linux init system from SysV to systemd to crontab.

The operator works on Windows and cross-compiles for Linux, targeting servers and IoT devices. The SELinux bypass is the standout technique -- using `ausearch + audit2allow + semodule` to auto-generate a permissive policy is something most incident responders would not check for, and it effectively neutralizes one of Linux's strongest security controls.

Despite the capability depth, the binary leaks everything through Go's pclntab: function names, file paths, source structure, and build metadata. A single GoReSym run + three YARA rules provides complete detection coverage. The operational security of the code is high; the build hygiene is not.

The Chaos/Kaiji family has been active since 2020 (Kaiji) with continuous evolution through the Ares variant. MalwareBazaar tracks 324+ samples under the Chaos signature. The Ares hacking group continues to operate DDoS-for-hire services with infrastructure rotated through Chinese-linked domains.

For defenders: monitor `/boot/System.mod`, `/lib/system-mark`, and the `quotaoff.service` systemd unit. Audit crontab for `/.mod` entries. Log `semodule` invocations. And run GoReSym on any stripped Go binary that shows up in your environment -- the pclntab will tell you exactly what it does.

---

## Disassembly: Inside the Attack Dispatcher

Using [gore](https://github.com/goretk/gore) (the library behind redress), we recovered the real code addresses for all 84 main package functions. The `attack()` function at `0x4d7c40` (3,296 bytes) is the central command router. After the Go stack check prologue, it parses the command string character by character using byte-level comparisons:

```asm
; attack() command dispatcher at 0x4d7c40
; After parsing attack parameters, it checks the command type string:

  4d7e20: cmp  rdi, 0x8             ; Command string length > 8?
  4d7e24: jg   0x4d8121             ; Jump to long-command handlers
  4d7e2a: cmp  rdi, 0x3             ; Length == 3?
  4d7e2e: jne  0x4d8060             ; If not, try other lengths

  ; 3-character command check: "Raw"
  4d7e34: cmp  word [rsi], 0x6152   ; First 2 bytes: "Ra" (little-endian)
  4d7e39: jne  0x4d7ee1             ; Not "Ra" -> try next
  4d7e3f: cmp  byte [rsi+2], 0x77   ; Third byte: "w"
                                     ; Match: "Raw" -> Ares_L3_Raw

  ; 3-character command check: "Tcp"
  4d7ee1: cmp  word [rsi], 0x6354   ; First 2 bytes: "Tc"
  4d7eec: cmp  byte [rsi+2], 0x70   ; Third byte: "p"
                                     ; Match: "Tcp" -> Ares_Tcp

  ; 3-character command check: "Udp"
  4d7f9f: cmp  word [rsi], 0x6455   ; First 2 bytes: "Ud"
  4d7faa: cmp  byte [rsi+2], 0x70   ; Third byte: "p"
                                     ; Match: "Udp" -> Ares_L3_Udp
```

The Go compiler optimizes string comparisons into cascading byte/word checks. Short commands ("Raw", "Tcp", "Udp") use 3-byte checks. Longer commands (like "TcpKeepHex" or "UdpPlainHex") are handled at the `jg 0x4d8121` branch for strings longer than 8 characters, with additional suffix checks at offsets 8 and 14.

### AES-CFB Decryption (main.DecryptCFB)

The `DecryptCFB` function at `0x4d0b60` (320 bytes) decrypts C2 traffic using AES in CFB (Cipher Feedback) mode. The Go calling convention passes the key in RAX/RBX, the ciphertext in RCX/RDI, and the IV in RSI/R8:

```asm
; main.DecryptCFB at 0x4d0b60 (320 bytes)
; AES-CFB decryption for C2 communication

  4d0b60: cmp  rsp, [r14+0x10]      ; Go stack guard check
  4d0b64: jbe  0x4d0c3c             ; Stack too small -> grow

  4d0b6a: sub  rsp, 0x58            ; Allocate 88 bytes stack frame
  4d0b78: mov  [rsp+0x78], rdi      ; Save ciphertext pointer
  4d0b82: mov  [rsp+0x60], rax      ; Save key buffer
  4d0b87: mov  [rsp+0x70], rcx      ; Save key length

  ; Create AES cipher from key
  4d0b8c: mov  rax, rdi             ; rax = ciphertext ptr
  4d0b8f: mov  rbx, rsi             ; rbx = ciphertext len
  4d0b92: mov  rcx, r8              ; rcx = IV
  4d0b95: call 0x476060             ; crypto/aes.NewCipher(key)

  ; Check IV length >= 16 bytes (AES block size)
  4d0ba0: cmp  rdx, 0x10            ; IV length >= 16?
  4d0ba4: jl   0x4d0c28             ; Too short -> panic

  ; Create CFB decrypter and decrypt
  4d0bb0: mov  edi, 0x10            ; Block size = 16
  4d0bba: mov  r8d, 0x1             ; decrypt flag = true
  4d0bc0: call 0x475100             ; crypto/cipher.NewCFBDecrypter

  ; Call the decryption via interface dispatch
  4d0bfd: mov  rdx, [rax+0x18]      ; Load XORKeyStream method ptr
  4d0c0d: call rdx                  ; Call XORKeyStream(dst, src)
```

The function validates that the IV is at least 16 bytes (the AES block size), then delegates to Go's standard `crypto/cipher.NewCFBDecrypter`. The indirect call at `0x4d0c0d` (`call rdx`) is a Go interface method dispatch -- it calls `XORKeyStream` through the `cipher.Stream` interface vtable.

### CPU Killer (main.Killcpu)

The `Killcpu` function at `0x4dde00` (320 bytes) is a denial-of-service tool that exhausts CPU resources:

```asm
; main.Killcpu at 0x4dde00 (320 bytes)
; Exhausts CPU by spawning tight-loop goroutines

  4dde18: mov  rax, -0x64           ; rax = -100 (SIGKILL target: nice value)
  4dde1f: lea  rbx, [rip+0x33da6]   ; "/proc" directory path
  4dde26: mov  ecx, 0x5             ; Path length = 5
  4dde2b: mov  edi, 0x2             ; O_RDONLY | O_DIRECTORY
  4dde32: call 0x4811e0             ; syscall.Open("/proc", ...)

  ; If /proc open fails, just spin
  4dde37: test rax, rax             ; File descriptor valid?
  4dde3a: jne  0x4dde90             ; Yes -> enumerate PIDs

  ; Set up CPU exhaustion loop
  4dde47: mov  eax, 0x46            ; Default threshold (70)
  4dde4c: mov  ecx, 0x50            ; Alternative threshold (80)
  4dde55: mov  [rsp+0x30], rax      ; Save threshold

  ; ... (spawns goroutines in tight loop)

  ; Inner loop: busy-wait consuming CPU
  4ddeb6: mov  eax, 0x77359400      ; 2,000,000,000 iterations
  4ddec0: call 0x4601c0             ; runtime.procyield(n) -- CPU spin
```

The function first opens `/proc` to enumerate running processes (for killing competitors via `kpid`). Then it enters a busy-wait loop calling `runtime.procyield` with 2 billion iterations, effectively locking a CPU core at 100%. The threshold values (70 and 80) likely correspond to CPU usage percentages -- the bot adjusts its behavior based on current system load.

### Shell Execution (main.Shell)

The smallest but most dangerous function -- `Shell` at `0x4e3100` (160 bytes) provides remote command execution:

```asm
; main.Shell at 0x4e3100 (160 bytes)
; Executes commands via /bin/sh

  4e3100: cmp  rsp, [r14+0x10]      ; Stack guard
  4e3106: sub  rsp, 0x50            ; 80-byte frame

  ; Set up exec.Command arguments
  4e3125: lea  rdx, [rip+0x2e79b]   ; "-c" argument string
  4e312c: mov  [rsp+0x28], rdx      ; args[0] = "-c"
  4e3131: mov  qword [rsp+0x30], 2  ; args length = 2
  4e313a: mov  [rsp+0x38], rax      ; args[1] = command string
  4e313f: mov  [rsp+0x40], rbx      ; args[1] length

  ; Load os/exec package interface
  4e3144: mov  rax, [rip+0x1080f5]  ; os/exec.Command function
  4e314b: mov  rbx, [rip+0x1080f6]  ; /bin/sh path

  ; Build command: exec.Command("/bin/sh", "-c", userCommand)
  4e3152: lea  rcx, [rsp+0x28]      ; Pointer to args slice
  4e3157: mov  edi, 0x2             ; Number of args
  4e3160: call 0x4cb5c0             ; os/exec.Command()

  ; Execute and capture output
  4e3165: call 0x4cca00             ; (*Cmd).CombinedOutput()
```

The function constructs `exec.Command("/bin/sh", "-c", <command>)` and calls `CombinedOutput()` to capture both stdout and stderr. The output is returned to the C2 via `Ares_send`. This is equivalent to the Python `subprocess.check_output(["sh", "-c", cmd])` pattern.

---

## Attribution

### Family Lineage

This sample belongs to the **Chaos** malware family, which is the direct successor to **Kaiji**. The lineage is well-documented:

**Kaiji (2020)** was the original Go-based DDoS bot, first discovered by [Intezer](https://intezer.com/blog/kaiji-new-chinese-linux-malware-turning-to-golang/) and [MalwareMusT](https://www.secrss.com/articles/18218). It targeted Linux servers and IoT devices via SSH brute force, with DDoS capabilities including SYN flood, ACK flood, UDP flood, and IP spoofing. Written entirely in Go, it was notable for being one of the first botnet families to abandon C/C++ for Golang. The function names and source structure showed clear Chinese-language development.

**Chaos (2022)** evolved from Kaiji with significant capability additions. [Lumen Black Lotus Labs](https://blog.lumen.com/chaos-is-a-go-based-swiss-army-knife-of-malware/) published the definitive analysis in September 2022, documenting the expanded feature set: Windows support (cross-compilation), CVE exploitation chains, cryptomining modules, SOCKS5 proxy, and improved persistence. They tracked the infrastructure to Chinese-operated C2 panels and observed attacks against financial, technology, and gaming targets.

**Ares variant (2023-present)** represents the operator group's branded fork. [QiAnXin XLab](https://ti.qianxin.com/blog/articles/Kaiji-Botnet-Resurfaces-Unmasking-Ares-Hacking-Group-EN/) identified the Ares hacking group operating 13+ active C2 panels as of March 2023, with the `Ares_*` function prefix as their signature. The group runs a DDoS-for-hire service and has been linked to attacks on Ukrainian targets and cryptocurrency platforms.

### Operator Profile

The evidence points to a **Chinese-speaking operator group** running a DDoS rental service:

- **Build environment**: Windows development machine (`C:/Program Files/Go/`, `C:/src/client/linux/`) cross-compiling for Linux -- consistent with a developer workstation, not a compromised server
- **C2 infrastructure**: `s4[.]quicklyspeed[.]com` resolving to `183[.]236[.]97[.]73` (China Telecom, Guangdong province). Historical Chaos C2 domains include `js.wanpay1[.]cn`, `a.nqb001[.]com`, and `xiaomai233.f3322[.]net` -- all Chinese-registered domains
- **Cross-platform compilation**: MCRIT analysis found a Windows PE variant (`ee0b9fbd...`) sharing 578 functions, compiled with Go 1.20.1 from the same source tree. The operator maintains a single codebase targeting both Linux servers and Windows endpoints
- **Allowlist feature**: The `(*Allowlist).Add/Del/Is` functions suggest a commercial operation -- paying customers' infrastructure is excluded from attacks
- **Code maturity**: 23 source files, clean modular architecture, 12 attack vectors with hex-encoded variants for evasion. This is an actively maintained toolkit, not a one-off project

### Timeline

| Date | Event | Source |
|---|---|---|
| May 2020 | Kaiji discovered targeting Linux/IoT via SSH brute force | [Intezer](https://intezer.com/blog/kaiji-new-chinese-linux-malware-turning-to-golang/) |
| Sep 2022 | Chaos identified as Kaiji successor with Windows support | [Lumen Black Lotus Labs](https://blog.lumen.com/chaos-is-a-go-based-swiss-army-knife-of-malware/) |
| Mar 2023 | Ares hacking group unmasked with 13+ C2 panels | [QiAnXin XLab](https://ti.qianxin.com/blog/articles/Kaiji-Botnet-Resurfaces-Unmasking-Ares-Hacking-Group-EN/) |
| Feb 2024 | Chaos persistence techniques documented (SELinux bypass) | [Sysdig](https://www.sysdig.com/blog/chaos-malware-persistence-evasion-techniques) |
| Apr 2026 | New Chaos variant targeting misconfigured cloud servers | [Help Net Security](https://www.helpnetsecurity.com/2026/04/08/chaos-malware-cloud-misconfigured-servers/), [Darktrace](https://www.darktrace.com/blog/darktrace-identifies-new-chaos-malware-variant-exploiting-misconfigurations-in-the-cloud) |
| Apr 11, 2026 | This sample first seen on MalwareBazaar | [MalwareBazaar](https://bazaar.abuse.ch/sample/a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd) |
| Apr 11, 2026 | Joe Sandbox dynamic analysis: Kaiji, score 84/100 | [Joe Sandbox](https://www.joesandbox.com/analysis/1896921/0/html) |

### References

- [Lumen Black Lotus Labs -- "Chaos is a Go-based Swiss Army Knife of Malware" (2022)](https://blog.lumen.com/chaos-is-a-go-based-swiss-army-knife-of-malware/)
- [QiAnXin XLab -- "Kaiji Botnet Resurfaces: Unmasking the Ares Hacking Group" (2023)](https://ti.qianxin.com/blog/articles/Kaiji-Botnet-Resurfaces-Unmasking-Ares-Hacking-Group-EN/)
- [Intezer -- "Kaiji: New Chinese Linux Malware Turning to Golang" (2020)](https://intezer.com/blog/kaiji-new-chinese-linux-malware-turning-to-golang/)
- [Sysdig -- "Chaos Malware: Persistence and Evasion Techniques" (2024)](https://www.sysdig.com/blog/chaos-malware-persistence-evasion-techniques)
- [Darktrace -- "New Chaos Variant Exploiting Misconfigurations in the Cloud" (2026)](https://www.darktrace.com/blog/darktrace-identifies-new-chaos-malware-variant-exploiting-misconfigurations-in-the-cloud)
- [Malpedia -- elf.kaiji](https://malpedia.caad.fkie.fraunhofer.de/details/elf.kaiji)
- [Black Lotus Labs IOCs (GitHub)](https://github.com/blacklotuslabs/IOCs/blob/main/Chaos_IoCs.txt)
- [Sekoia -- "Advent of Configuration Extraction: Kaiji" (2023)](https://blog.sekoia.io/advent-of-configuration-extraction-part-1-pipeline-overview-first-steps-with-kaiji-configuration-unboxing/)
- [VirusTotal community comments and sandbox results](https://www.virustotal.com/gui/file/a2ce4bfd8411324b10576d228b04cb8036e61b998ae9162e6f81ab65cf7416bd)

---

*Tools used: GoReSym (Go symbol recovery), gore (function address recovery), redress (source code projection), objdump (disassembly), strings (IOC extraction), custom Python pclntab analysis. All sandbox results cited from VirusTotal community contributors: joesecurity, JaffaCakes118, NeikiAnalytics, NucleonSecurity, petik, and thor (Florian Roth).*
