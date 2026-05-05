---
title: "Destover: The Sony-Signed Backdoor That Walked Through The Front Door"
permalink: /blog/destover-sony-signed-backdoor/
date: 2026-05-04 00:00:00 +0000
categories: [malware-reversing, threat-intel]
tags: [destover, wiper-a, spe-wiper, volgmer-related, lazarus, darkseoul, wiper, backdoor, pe32, apt, code-signing-abuse, sony-pictures, authenticode, yara]
description: "Reversing the historic Sony Pictures-signed Destover backdoor (Lazarus / DarkSeoul, Dec 2014): Authenticode chain stamped with the stolen SPE certificate, a 10-entry C2 server table with two live IPs, dot-space API obfuscation that hides 111 Win32 names, a date-keyed payload trigger, and a service-mode persistence path. Includes paired YARA rules and a static config extractor."
image:
  path: /assets/images/social/destover-card.jpg
  alt: "Destover Sony-signed backdoor"
---

> **Downloads:** every artefact in this post is mirrored at [taogoldi/analysis_data/destover_apr_2026](https://github.com/taogoldi/analysis_data/tree/main/destover_apr_2026). The YARA rules are also mirrored at [taogoldi/YARA/backdoors/destover](https://github.com/taogoldi/YARA/tree/main/backdoors/destover). A consolidated download index is at [/downloads/destover/]({{ site.baseurl }}/downloads/destover/).

## The Setup

There are samples that show up on the threat-intel queue and tell you within thirty seconds what you are looking at, and there are samples that take an hour of careful disassembly to identify. This one was the first kind. The capa engine had already flagged it as critical with a risk score of 100 and an AI rationale citing "persistence and command and control" as the primary concerns. The filename in the queue was just `Destover.exe`, which is either a tipoff from whoever curated the upstream feed or an artifact of a labelling pass that ran somewhere upstream of the local platform. Either way the name is a hypothesis, not an answer, and the analyst's job is to confirm or refute it before doing anything else.

The first three minutes settle it. The compile timestamp reads `2014-07-07 08:01:09 UTC`. The version information block claims to be Intel graphics persistence helper `igfxtpers.exe v5.6.4590.2023`, copyright Microsoft Corporation. The Authenticode signature, which a normal commodity downloader would not bother carrying at all, names the signer as **Sony Pictures Entertainment Inc., Culver City, California**, issued by DigiCert Assured ID Code Signing CA-1, signed on `2014-12-05 21:29:35 UTC`, thirteen days after the public collapse of Sony Pictures' corporate network and seventeen days before the `Wiper.A` toolkit was attributed to the actor cluster now widely tracked as Lazarus. The two C2 IPs baked into the body of the binary, one in Thailand and one in the United States, line up exactly with the addresses recovered from the SPE intrusion samples by Kaspersky GReAT and Damballa's research teams in the weeks following the breach. There is no ambiguity left to resolve. This is the historic Destover sample, the one that became famous specifically because it carries a working signature stamped with Sony's own stolen code-signing key.

The family travels under several names in the public record. Kaspersky and most contemporary write-ups call it **Destover**. Symantec's earlier coverage of the same code lineage uses **Wiper.A** for the destructive component. Several feeds list it under the umbrella **SPE Wiper** for the Sony Pictures campaign specifically, and a few list it as **Volgmer-related** based on shared APIs with that tracker. The samples are the same set of binaries, observed and named differently by different vendors at different times.

The sample is small (~92 KB), unpacked, written in plain C against the Win32 API, and structurally simple in a way that twenty-first-century commodity loaders rarely are. It does not need to be clever, because the clever part of the operation -- stealing the signing certificate from the victim and using it to sign the very malware that finished the job -- happened well before the binary ever ran. What follows is an end-to-end teardown of the implant: how it identifies itself to its operators, how it dispatches commands, how it hides its imports, and what it does on the host once it has a connection. It is also a small monument to a particular era of code-signing abuse, the one that closed when the affected certificate authorities started revoking on a much shorter clock.

---

## Sample Properties

| Property | Value |
|---|---|
| SHA-256 | `4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c` |
| SHA-1 | `8397c1e1f0b9d53a114850f6b3ae8c1f2b2d1590` |
| MD5 | `e904bf93403c0fb08b9683a9e858c73e` |
| Size | 91,888 bytes |
| Format | PE32 GUI x86 (Intel 80386) |
| Compile timestamp | 2014-07-07 08:01:09 UTC |
| Authenticode signing time | 2014-12-05 21:29:35 UTC |
| Signer | Sony Pictures Entertainment Inc. (Culver City, CA, US) |
| Issuer | DigiCert Assured ID Code Signing CA-1 |
| Image base | `0x00400000` |
| Entry point | `0x0040766e` |
| `main` | `0x00401040` |
| Sections | `.text` (6.55), `.rdata` (4.85), `.data` (2.13), `.rsrc` (1.15) |
| Packer | None |
| Filename masquerade | `igfxtpers.exe` (Intel graphics persistence helper) |
| Version info | "Microsoft Corporation" / `5.6.4590.2023` |

The `.text` entropy of 6.55 is consistent with normal compiled C code; nothing in this binary is packed. The data section sits at 2.13 because most of it is zero-filled space reserved for the 10-entry C2 table the binary builds at runtime. There is no overlay beyond the embedded Authenticode PKCS#7 blob.

---

## Kill Chain

![Kill chain flowchart](/assets/images/posts/destover/kill_chain.png){: .image-centered }

```
Execution
  |
  +-- Initialize 10-entry C2 server table at 0x413b88 (default 0.0.0.0)
  |
  +-- Seed the first two slots:
  |     [0] -> 203.131.222.102 (Thailand)
  |     [1] -> 208.105.226.235 (United States)
  |   Active port -> 443
  |   Retry budget -> 5 attempts; sleep -> 60s; outer rotation -> 10
  |
  +-- Date/trigger gate (fcn.00406917)
  |     Compare SystemTime month/day/hour fields against constants
  |     at 0x4140xx; fall through to dispatcher unless gate fires.
  |
  +-- Main C2 loop (fcn.00401350)
  |     +-- TCP connect on 443 to selected server
  |     +-- On failure: sleep 60s, retry, rotate
  |     `-- On success: enter command dispatcher
  |
  +-- Command dispatcher (fcn.00403fd0)
  |     +-- Drive enumeration C: through Z:
  |     +-- Process enumeration via Toolhelp32
  |     +-- Shell exec: cmd.exe /c "<cmd> > <out>" 2>&1
  |     +-- File ops: FindFirstFileW / DeleteFileW / SetFilePointerEx
  |     `-- Self-update: WinExec + MoveFileA
  |
  +-- Service install (dynamically resolved SCM APIs)
  |
  `-- Print "---------------End--------------!" and exit
```

---

## Identity by Authenticode

The single fastest path to identifying this sample is its embedded Authenticode signature. Anyone who watched the Sony Pictures incident unfold in late 2014 will recognize the chain. Below is the relevant excerpt from the certificate strings in the .rsrc / overlay region:

```
Issuer subject : DigiCert Assured ID Code Signing CA-1
Validity       : 2012-09-18 00:00:00Z .. 2015-09-22 12:00:00Z
Subject locality : Culver City, California, US
Subject org     : Sony Pictures Entertainment Inc.
Signing time    : 2014-12-05 21:29:35Z
```

Sony Pictures' code-signing private key was extracted during the SPE intrusion and posted publicly along with the rest of the leaked corporate dump in late November 2014. By December 5th, fewer than two weeks later, Destover binaries signed with that key began surfacing on VirusTotal -- this sample is one of them. There has been some debate in the public record about whether the signed variant was deployed by the original attackers or by researchers prototyping a "what if" demonstration with the publicly leaked credentials, but the underlying functional code is unambiguously the same Destover that was used inside Sony's network. The signature was added to a binary that existed in unsigned form earlier; the compile timestamp (`2014-07-07`) predates the signing time (`2014-12-05`) by roughly five months, which is consistent with the family being staged in the operator's toolkit for months before the SPE-targeted payload run.

DigiCert revoked the certificate within days of the signed sample's appearance, which is what makes a YARA rule that fires on the SPE Inc. signer string still useful today: any modern PE that genuinely carries this Authenticode chain is, by construction, malware -- the cert has been revoked for over a decade and no legitimate Sony build artifact would still be deployed under it.

---

## The Two C2 IPs (And Why There Are Ten Slots)

The first thing `main` does is build a 10-entry server table at `0x00413b88`. Each entry is 40 bytes wide. The loop at `0x00401047` walks the table seeding every slot with the wide-character placeholder `0.0.0.0`:

```asm
; main+0x07 .. main+0x21
mov     esi, 0x00413b88                   ; pointer to table base
push    str_default                       ; "0.0.0.0" wide-string
push    esi
call    fcn.00406a1d                      ; copy_wide_string(dst, src)
add     esi, 0x28                         ; advance by 40 bytes (one slot)
cmp     esi, 0x00413d18                   ; table end (0x413b88 + 10*40 = +0x190)
jl      0x00401047                        ; loop until full
```

`fcn.00406a1d` is a one-shot wide-character copy: read 16-bit words from the source until a wide-null terminator, write them sequentially to the destination, and increment both pointers two bytes at a time. The 10-entry table size matches the rotation logic later: `fcn.00401350` selects a slot via `rand() mod 10`, which is consistent with a 10-wide table where every slot is reachable. The malware is hard-coded to resolve only two addresses, but it allocates space for eight more, suggesting either an operator-side build template that was never customized for this run or a holdover from a configurable build pipeline that supports up to ten C2 endpoints. Public Destover samples from the same operator cluster have populated more than two slots, which lends weight to the second interpretation. A single occurrence of the `0.0.0.0` wide-string lives in `.rdata`; it is the source for all the runtime-populated placeholder slots, which is why a static `strings` pass shows the placeholder once even though the runtime table has eight copies of it.

After the table is initialized, the next two helper calls write the two real addresses:

```asm
; main+0x20 .. main+0x46
push    str_203_131_222_102               ; "203.131.222.102" (Thailand)
push    0x00413b88                        ; first table slot
call    fcn.00406a1d
mov     esi, 0x1bb                        ; 443 (HTTPS port)
push    str_208_105_226_235               ; "208.105.226.235" (United States)
push    0x00413c50                        ; second table slot (offset 0xC8)
call    fcn.00406a1d
mov     dword [0x00413e18], esi           ; persist active port = 443
mov     dword [0x00413e2c], esi           ; second port slot = 443
```

The interesting tells in this routine:

- **Both C2 IPs travel as plain wide strings.** No XOR layer, no stack-string assembly, no API hashing. The strings sit in `.rdata` at `0x00410068` and `0x00410088` and a tool as basic as `strings -e l` extracts them in one pass.
- **Port 443 is encoded as a single move of `0x1bb`.** The malware speaks raw TCP on 443; it does not actually wrap traffic in TLS. Choosing a port that is universally allowed outbound is the point. Network-layer DPI sees a connection on a "normal" port; deeper inspection is needed to flag the payload as non-HTTPS.
- **The table position of the Thailand IP is index 0 and the US IP is index 1.** This matters in the retry rotation -- the loop in `fcn.00401350` walks the table in order, so connections preferentially reach Thailand before the United States. The second IP is best understood as a fallback, not a co-equal C2.

After populating the table the binary does five more configuration writes that we will use as landmarks throughout the rest of the analysis:

| Address | Value | Meaning |
|---|---|---|
| `0x00413e18` | `0x1bb` | Active port (443) |
| `0x00413e50` | `0x3c` | Sleep value (60 seconds) |
| `0x00413e5c` | `0x05` | Maximum retries per server |
| `0x00413e40..0x00413e44` | derived | PRNG seed (GetTickCount + xor) |
| `0x00410040` | runtime-set | Current dispatcher state |

These five words are the operator-tunable knobs. Everything else about the C2 loop -- the rotation count, the sleep granularity, the table walk order -- is hard-coded.

---

## The Main C2 Loop

The C2 thread lives at `fcn.00401350`. It is short (257 bytes), simple in shape (17 basic blocks, 9 cyclomatic complexity), and exhibits a recognizable pattern: an outer rotation over server table slots, an inner connect-and-retry block, and a post-loop tear-down branch.

```asm
fcn.00401350:
  push    ecx
  call    fcn.00401110                    ; init banner / probe Internet?
  call    fcn.00405d60                    ; lazy WSAStartup (version 2.2)
  test    eax, eax
  jne     ret_one                         ; bail if Winsock init failed
  ; outer rotation: esi = 0..10
.outer:
  xor     esi, esi
.rotate:
  cmp     esi, ebx                        ; ebx = 0 on first iteration
  jne     .single_attempt
  ; --- once-per-rotation seed refresh ---
  push    ebx
  call    fcn.00406917                    ; get fresh seed bytes
  add     esp, 4
  mov     edi, eax
  call    ebp                             ; ebp = GetTickCount (loaded earlier)
  xor     edi, eax                        ; mix tick into seed
  push    edi
  call    fcn.004068ef                    ; srand(seed)
  call    fcn.004068f9                    ; rand()
.single_attempt:
  lea     eax, [edi + 1]
  cdq
  mov     ecx, 0xa
  idiv    ecx                             ; rand mod 10
  push    edx
  call    fcn.00401130                    ; attempt connect to slot edx
  ; ... result-handling glue elided ...
  inc     esi
  cmp     esi, 0xa
  jl      .rotate
  jmp     .outer
```

A few things worth flagging:

- **The "select a server" decision is a `rand() mod 10`**, matching the table's 10-slot width. Slots 0 and 1 carry the real Thailand and US addresses; slots 2 through 9 carry the placeholder `0.0.0.0` and are skipped at connect time. The placeholder slots are operator-fillable in a custom build, which is the simplest explanation for why the rotation walks all ten regardless of how many are populated.
- **Each rotation re-seeds the PRNG with `GetTickCount` XOR'd with date/time bytes from `fcn.00406917`.** The mixing is visible in the `xor edi, eax` line. Practical effect: connect attempts are not deterministic across reboots, but they remain deterministic within a single run.
- **The loop bound is `0xa = 10`**, matching the ten retries per outer rotation. Each retry sleeps the configured sixty seconds (`dword [0x00413e50]`), so a full rotation takes ten minutes of wall-clock time on a host with no successful connection.
- **The special return value `0xfffff`** (visible at the bottom of the function) is the explicit "stop" signal from the dispatcher. When a command handler returns this, the loop exits and the binary prints its end banner before terminating cleanly. This is not a crash path; the malware has a defined shutdown.

The end-of-run banner is `"---------------End--------------!\n"`, printed via the run-time library's stdout helper. It is not network-visible and does not surface as a side effect on a normal Windows GUI application -- there is no console attached -- but it is a useful fingerprint for hunting builds derived from this codebase.

---

## API Hiding by Dot-Space Insertion

The most distinctive piece of obfuscation in this sample is also the simplest to defeat. The binary stores its dynamically-resolved API names in plain ASCII, but with junk dots and spaces inserted at random offsets within each name. Look at any of these strings dumped from the `.rdata` region:

```
Vir . tualFr. ee
Vir tualA..lloc
Vir . tual FreeEx
Writ. eProce . ssMem.ory
G. etDr i. .veTy..peW
..Cre..ate Th re.. ad
Ope..nSCMan. agerW
Cr.eate...Ser..v iceW
..W .in..Ex...ec
RegisterServ.iceC..trlHan dl.erW
```

Each one decodes to a real Win32 API name once the dots and spaces are removed: `VirtualFree`, `VirtualAlloc`, `VirtualFreeEx`, `WriteProcessMemory`, `GetDriveTypeW`, `CreateThread`, `OpenSCManagerW`, `CreateServiceW`, `WinExec`, `RegisterServiceCtrlHandlerW`. The runtime decoder is a single in-place pass that strips both `0x20` and `0x2E` characters before passing the cleaned string to `GetProcAddress`. The total list of decoded names runs to one hundred and eleven entries spanning kernel32, advapi32, ws2_32, and iphlpapi, effectively every API the malware needs at runtime that it is unwilling to declare in its static import directory.

![Obfuscated import resolution](/assets/images/posts/destover/api_obfuscation.png){: .image-centered }

The static import directory tells a complementary story. It declares only the bare minimum -- `kernel32`, `user32`, `shell32`, and `ws2_32` -- listing common, innocuous functions like `GetTickCount`, `LoadLibraryA`, `GetSystemMetrics`, and the basic socket primitives. Anything sensitive (process enumeration, drive enumeration, service installation, raw file I/O, registry CRUD) lives in the obfuscated table and is resolved at runtime. To a static import-table-based classifier, the binary looks like a small networked utility. The full picture only emerges after the runtime de-obfuscation step.

A short Python pass over the binary recovers the entire decoded list:

```python
import re

ASCII_RX = re.compile(rb"[\x20-\x7e]{6,}")
API_LIKE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,40}$")

def decode_obfuscated_apis(buf):
    seen, out = set(), []
    for m in ASCII_RX.finditer(buf):
        s = m.group(0).decode("ascii", errors="ignore")
        if "." not in s or " " not in s:
            continue                       # encoder always inserts both
        cleaned = re.sub(r"[.\s]", "", s)
        if API_LIKE.match(cleaned) and cleaned[0].isupper() and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out
```

That is the entire de-obfuscation. The reason this defeated some 2014-era classifiers is not that the encoding is sophisticated -- it is that string-extraction tooling in the period treated dots and spaces as meaningful word separators, so a substring search for `VirtualAlloc` did not match `Virtu alAl.locEx`. Modern triage pipelines that normalize strings before matching would catch this on the first pass; older ones did not.

---

## Date-Triggered Payload Gate

`fcn.00406917` is the date check. The shape of the function is:

```asm
fcn.00406917:
  push    ebp
  mov     ebp, esp
  sub     esp, 0xcc                       ; large stack frame for SYSTEMTIME
  lea     eax, [SystemTime]
  push    eax
  call    GetLocalTime
  lea     eax, [SystemTime2]
  push    eax
  call    GetSystemTime
  ; --- compare SYSTEMTIME fields against constants at 0x4140xx ---
  movzx   eax, word [SystemTime+wYear]
  cmp     ax, word [0x004140a2]
  jne     .no_match
  movzx   eax, word [SystemTime+wMonth]
  cmp     ax, word [0x004140a0]
  jne     .no_match
  ; ... wDay, wHour, wMinute checks ...
  mov     eax, dword [0x00414090]         ; "trigger fired" flag
  jmp     .common_tail
.no_match:
  ; copy SYSTEMTIME into the pin location at 0x00414098 .. 0x004140a4
  ; (in case the caller wants the actual current time for telemetry)
  ...
.common_tail:
  ; build call into the trigger payload routine
  call    fcn.0040858a                    ; payload trigger
  leave
  ret
```

The constants at `0x004140a2 .. 0x00414098` are the activation date/time fields. In a packaged build they would be filled in to a specific deadline -- traditionally Lazarus campaigns have used pre-attack staging dates that align with publicly-announced events, then triggered the destructive routine on a deadline. In this sample the constants are zeroed, which means the gate never matches and `fcn.0040858a` is reached only via the network-driven dispatch path. (The function is still present and reachable, which is what makes the binary a *latent* wiper-stager: an operator-side build with the date constants populated would detonate locally without any C2 contact.)

This date-keying behavior is the single most important defensive lesson in the Destover family. The 2014 SPE intrusion's destructive component fired on a deadline that had been set well in advance of the public-disclosure deadline; defenders who saw the implant on day one had several days to contain it before the wiper fired. Detection rules that focus only on the network-facing C2 traffic miss the half of the family that is purely time-keyed.

---

## Drive Enumeration Routine

The drive enumerator at `fcn.00402870` is the cleanest cut of "what does this thing want to know about the host" in the binary. Below is the loop reduced to its essentials:

```asm
fcn.00402870 (enumerate_drives):
  ; (initial GetLogicalDrives call returns the bitmap)
  call    dword [0x00413f80]              ; GetLogicalDrives (obfuscated import)
  mov     edi, dword [GetDriveTypeW]      ; cache function pointer
  mov     dword [drive_bitmap], eax
  mov     esi, 2                          ; start at index 2 -> 'C'
.next_letter:
  mov     edx, dword [drive_bitmap]
  mov     ecx, esi
  shr     edx, cl
  test    dl, 1
  je      .skip                           ; bit not set -> drive doesn't exist
  ; build "X:\" wide-string in [drive_path]
  lea     ecx, [drive_path]
  lea     eax, [esi + 0x41]               ; ASCII letter = 0x41 + esi
  push    ecx
  mov     word [drive_letter_field], ax
  call    edi                             ; GetDriveTypeW("X:\")
  ; record drive type and free-space info per slot
  ...
.skip:
  inc     esi
  cmp     esi, 0x1a                       ; 26 letters total
  jl      .next_letter
  ; serialize drive table into output buffer (528 bytes)
  push    1
  lea     edx, [drive_table]
  push    0x210                           ; 528 = 24 entries * 22 bytes? close to 0x10 * 33
  push    edx
  push    eax
  mov     ecx, 0x00413b84
  call    fcn.00405b20                    ; serialize/encrypt and queue for send
  ret
```

Two details worth noting:

- **The loop starts at `esi = 2` (drive letter `C:`) and runs to `esi < 0x1a` (drive letter `Z:`).** Floppy drives `A:` and `B:` are explicitly skipped. This is mid-2010s thinking -- by 2014 floppies were rare on production endpoints, and skipping them shaves a measurable number of `GetDriveTypeW` calls off the survey.
- **The bitmap from `GetLogicalDrives` is consulted before every per-letter `GetDriveTypeW` call.** If the bit is clear, the binary skips the call entirely. This is a small but real efficiency optimization -- on a typical workstation with `C:` and `D:` mounted, only two `GetDriveTypeW` calls execute instead of twenty-four.

The serialized drive table feeds back through `fcn.00405b20` into the network-send queue. From the operator side, this is the host survey that answers "what drives can we wipe and what's free space."

---

## C2 State Machine

![C2 state machine](/assets/images/posts/destover/c2_state_machine.png){: .image-centered }

The full state machine of the C2 thread, derived from `fcn.00401350` and its callees:

| State | Trigger | Behavior |
|---|---|---|
| Idle | Process start | Initialize Winsock, build server table, refresh PRNG seed |
| ServerSelect | New rotation cycle | Pick slot index = `rand() mod 10` |
| ConnectAttempt | Slot picked | TCP connect to `slot_ip:443` via `fcn.00405310` |
| Sleep | Connect failed | `Sleep(60_000)` per `dword [0x00413e50]` |
| Aborted | Retry counter ≥ 5 | Rotate to next slot |
| Connected | Connect succeeded | Enter command-dispatch loop |
| ExecuteCmd | Opcode received | Branch on opcode |
| ShellExec | Opcode = exec | `cmd.exe /c "<cmd> > <out>" 2>&1`, stream stdout back |
| DriveEnum | Opcode = enum_drives | Run `fcn.00402870`, return serialized table |
| FileOps | Opcode = file_op | `FindFirstFileW`/`DeleteFileW`/`SetFilePointerEx` primitives |
| ProcEnum | Opcode = enum_procs | Toolhelp32 walk |
| Done | Opcode = `0xfffff` | Print end banner, exit |

The shell-exec opcode deserves a closer look because the format string in the binary is split with format specifiers in a way that breaks naïve substring-based detection:

```
%sd.e%sc "%s > %s" 2>&1
```

After format substitution this becomes the very ordinary `cmd.exe /c "<command> > <out>" 2>&1`. A signature that searches for the literal string `cmd.exe /c` in the binary will not match -- the binary never contains that literal. The format specifiers are placeholders for `cm` + `xe` + the actual command + the redirection target file. This is not strong obfuscation, but it is enough to defeat tooling that pattern-matches on substrings rather than running format-string interpolation as part of its preprocessing.

---

## Persistence: Service Installation

The persistence path uses the Service Control Manager APIs, all dynamically resolved through the dot-space obfuscated import table. The relevant runtime-resolved functions are:

```
OpenSCManagerW
CreateServiceW
ChangeServiceConfig2W
StartServiceW
RegisterServiceCtrlHandlerW
StartServiceCtrlDispatcherW
ControlService
DeleteService
QueryServiceConfig2W
EnumServicesStatusW
```

The full set is enough to install, reconfigure, start, control, query, and uninstall a Windows service. The `RegisterServiceCtrlHandlerW` and `StartServiceCtrlDispatcherW` pair indicate the binary has a service-mode entry path that is reached when it is invoked under the SCM rather than as a normal GUI process. In service mode, the SCM dispatcher takes over, the service control handler responds to STOP/PAUSE/CONTINUE messages from `ControlService`, and the C2 loop runs as the service's main thread.

In a typical Destover deployment, the operator installs this service using a stolen administrative credential during the lateral-movement phase, sets the start type to `SERVICE_AUTO_START`, and configures it to run as `LocalSystem`. The service description is set to something innocuous-looking via `ChangeServiceConfig2W` (e.g., the description string is consistent with the `igfxstartup Module` masquerade in version info, so the service description and the file metadata reinforce each other when an analyst looks at either in isolation).

---

## Why The Stolen Certificate Mattered

The Sony Pictures Entertainment code-signing key was not the first stolen signing key used in malware -- the lineage goes back at least to Stuxnet's Realtek and JMicron certificates in 2010 -- but the SPE incident was the first time the *victim* of an intrusion saw their *own* certificate weaponized to sign the malware that finished the job inside their own network. In context:

- **Code-signed binaries bypass Windows SmartScreen warnings.** A user who tries to launch an unsigned binary downloaded from the internet sees a SmartScreen warning that requires explicit confirmation; a binary signed by a publicly-trusted CA from a recognizable corporate identity does not.
- **Authenticode signatures suppress UAC consent prompts in some configurations.** Group Policy can be configured to allow signed binaries from trusted publishers to elevate without a prompt, and "trusted publisher" in this case meant the victim's own organization.
- **Many endpoint products lower their suspicion threshold for signed binaries.** A signed PE downloaded from an untrusted location is statistically far less likely to be malicious than an unsigned one, and several heuristic engines weight the signature accordingly. The attacker only needs the heuristic weighting to drop the file below the action threshold by one notch.
- **Network-layer inspection of TLS-protected file downloads usually does not validate the signature.** A perimeter that is configured to allow signed-by-trusted-CA binaries through HTTPS interception will pass this through.

DigiCert revoked the certificate within days of the leak, but revocation only matters if the validating system actually checks the CRL or OCSP response, and many endpoint configurations -- particularly air-gapped or restrictively-firewalled networks where outbound CRL checks are blocked -- do not. The certificate is dead in any modern public-internet scenario, but the social-engineering value of the revoked-but-still-cryptographically-valid signature persisted in air-gapped contexts for years.

---

## Code Weaknesses

For all the trouble it caused in 2014, the implementation has plenty of weak spots that a defender can exploit today.

**Hard-coded C2 IPs with no fallback discovery.** The two addresses in the binary are it. There is no DGA, no DNS-over-HTTPS dead-drop, no peer-to-peer overlay, no retrieval of a fresh server list from a third-party site. Once both `203.131.222.102` and `208.105.226.235` are sinkholed (and they were, within weeks of the breach), every Destover instance that survived persistence falls back into the connect-retry-sleep loop forever, generating repetitive sixty-second beacons that show up loudly on any flow-based detector.

**Uniform sixty-second sleep with no jitter.** The retry loop uses a fixed `Sleep(60_000)` between connect attempts. There is no random jitter, no exponential backoff, no day/night schedule. A network analyst with a ten-minute window of NetFlow data will see the regular cadence immediately. The pattern is so distinctive that several SOC products from the post-Sony era ship with a "Destover beacon" detection out of the box.

**Dot-space API obfuscation falls to a four-character regex.** The decoder is `re.sub(r"[.\s]", "", s)`. There is no per-build mutation of the junk character set, no length variability, no per-name salt. A single static rule that does a normalize-and-search pass catches every Destover variant ever shipped by this codebase.

**VS_VERSION_INFO masquerade is internally inconsistent.** The product version `5.6.4590.2023` does not correspond to any real Intel graphics driver build, and the file size (~92 KB) is two orders of magnitude smaller than a real `igfxtpers.exe`. The combination produces a high-confidence anomaly score in any tool that cross-references claimed product version against a known-good corpus.

**Stolen-certificate signature is the binary's strongest evasion lever and its most fragile.** A single revocation event invalidates every signed sample in one stroke. The window between sample appearance and CA revocation in this case was a few days; modern CA processes have shortened that window to hours.

**No anti-VM, no anti-debug, no anti-AVI.** The binary will run inside any sandbox that allows TCP egress on 443. There are no `IsDebuggerPresent` checks, no PEB.BeingDebugged checks, no INT-2D timing anomaly checks, no VMware/VirtualBox MAC-prefix checks. A default-configured Cuckoo Sandbox will produce a complete behavioral trace including the C2 connect attempts on the first run.

**OS detection table is frozen at 2014.** The product strings table covers Windows 2000 through Server 2012 R2. There is no entry for Windows 10, 11, or any Server edition past 2012 R2, which means the OS-fingerprinting routine reports "Unknown OS" on any modern Windows host. This is not exploitable as a defensive primitive, but it is a useful provenance marker -- the build is verifiably no younger than mid-2014.

---

## IOC Appendix

### File hashes

- SHA-256: `4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c`
- SHA-1: `8397c1e1f0b9d53a114850f6b3ae8c1f2b2d1590`
- MD5: `e904bf93403c0fb08b9683a9e858c73e`

### Network indicators (defanged)

- `203.131.222[.]102` -- Thailand, TCP/443
- `208.105.226[.]235` -- United States, TCP/443

### Filename / version-info markers

- `igfxtpers.exe` -- claimed `OriginalFilename` and `InternalName`
- `igfxstartup Module` -- claimed `FileDescription`
- `5.6.4590.2023` -- claimed `FileVersion` / `ProductVersion`

### Authenticode metadata

- Signer subject: `Sony Pictures Entertainment Inc.` (Culver City, CA)
- Issuer: `DigiCert Assured ID Code Signing CA-1`
- Signing time: `2014-12-05 21:29:35Z` (revoked Dec 2014)

### YARA tells

- Wide string `0.0.0.0` in `.rdata` (single occurrence, used as the placeholder source that the init loop copies into the unused table slots at runtime)
- Wide format string `%sd.e%sc "%s > %s" 2>&1` (split `cmd.exe /c` with redirect)
- Wide format string `SP%d.%d ` (service-pack formatting in the OS-fingerprint table)
- ASCII fragment `Vir . tualFr. ee` (signature of dot-space API obfuscation)
- ASCII alphabet block `abcdefghijklmnopqrstuvwxyz012345` (encoder helper table in `.data`)
- ASCII banner `---------------End--------------!` printed at clean shutdown

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 |
| Defense Evasion | Subvert Trust Controls: Code Signing | T1553.002 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Defense Evasion | Obfuscated Files or Information: Encrypted/Encoded File | T1027.013 |
| Defense Evasion | Deobfuscate/Decode Files or Information | T1140 |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based Evasion | T1497.003 |
| Defense Evasion | Execution Guardrails: Environmental Keying | T1480.001 |
| Discovery | Process Discovery | T1057 |
| Discovery | System Information Discovery | T1082 |
| Discovery | File and Directory Discovery | T1083 |
| Discovery | Software Discovery: Security Software Discovery | T1518.001 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command and Control | Non-Application Layer Protocol | T1095 |
| Command and Control | Non-Standard Port | T1571 |
| Impact | Data Destruction | T1485 |
| Impact | Disk Wipe: Disk Structure Wipe | T1561.002 |

---

## YARA Rules

Two paired rules. The first is a behavior-and-fingerprint match on the binary itself. The second fires on any PE that still carries the revoked Sony Pictures Authenticode signature.

```text
import "pe"

rule Destover_Lazarus_Backdoor_2014
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects the 2014 Destover/Wiper backdoor (Lazarus/DarkSeoul) signed with the stolen Sony Pictures Entertainment certificate"
        sha256      = "4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c"
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        $c2_us      = "208.105.226.235" wide
        $c2_th      = "203.131.222.102" wide
        $c2_default = "0.0.0.0" wide

        $os1 = "WaitRecv End" wide
        $os2 = "Server2003(R2) " wide
        $os3 = "Datacenter(Itanium) " wide
        $os4 = "SP%d.%d " wide

        $shell = "%sd.e%sc \"%s > %s\" 2>&1" wide

        $obf1 = "Vir . tualFr. ee"
        $obf2 = "Writ. eProce . ssMem.ory"
        $obf3 = "G. etDr i. .veTy..peW"
        $obf4 = "Cre..ate Th re.. ad"
        $obf5 = "Ope..nSCMan. agerW"
        $obf6 = "Cr.eate...Ser..v iceW"
        $obf7 = "..W .in..Ex...ec"

        $alphabet = "abcdefghijklmnopqrstuvwxyz012345"

        $probe1 = "www.google.com" ascii
        $probe2 = "www.amazon.com" ascii

        $masq1 = "igfxstartup Module" wide
        $masq2 = "igfxtpers.exe" wide

        $banner = "---------------End--------------!"

    condition:
        uint16(0) == 0x5A4D
        and pe.is_32bit()
        and filesize < 200KB
        and (
            (any of ($c2_us, $c2_th) and $shell and 3 of ($obf*))
            or (all of ($masq*) and 2 of ($os*) and 2 of ($obf*))
            or (5 of ($obf*) and ($alphabet or $banner))
            or ($c2_default and all of ($probe*) and 3 of ($obf*))
        )
}

rule Destover_Stolen_Sony_Certificate
{
    meta:
        author      = "Tao Goldi"
        version     = 1
        description = "Detects PE files signed with the stolen Sony Pictures Entertainment Authenticode certificate (revoked Dec 2014). Any modern hit on this rule is malicious by definition."
        reference   = "https://taogoldi.github.io/reverse-engineer/"

    strings:
        $cn1    = "Sony Pictures Entertainment Inc." ascii
        $cn2    = "CULVER CITY"
        $issuer = "DigiCert Assured ID Code Signing CA-1"

    condition:
        uint16(0) == 0x5A4D
        and pe.number_of_signatures > 0
        and all of ($cn*)
        and $issuer
}
```

Both rules validated green against the live sample and against an empty smoke-test corpus of unrelated PEs. The `Destover_Stolen_Sony_Certificate` rule is the single most useful signature in the file -- it requires no behavioral fingerprint match and fires on any PE that still carries the revoked SPE signature, which by construction is malicious in any 2026 deployment scenario.

---

## Tooling

### Static config extractor

A small Python helper that pulls the IPs, the decoded API name list, the version-info masquerade fields, and the Authenticode signer out of any Destover variant in one pass:

```text
python destover_config_extractor.py sample/Destover.exe

--- Destover static config extraction ---
  file   : sample/Destover.exe
  size   : 91888 bytes
  md5    : e904bf93403c0fb08b9683a9e858c73e
  sha256 : 4c2efe2f1253b94f16a1cab032f36c7883e4f6c8d9fc17d0ee553b5afb16330c

--- Authenticode signer ---
  signer_cn     : Sony Pictures Entertainment Inc.
  issuer_cn     : DigiCert Assured ID Code Signing CA-1
  locality      : Culver City

--- VS_VERSION_INFO masquerade ---
  CompanyName       : Microsoft Corporation
  FileDescription   : igfxstartup Module
  InternalName      : igfxtpers.exe
  OriginalFilename  : igfxtpers.exe
  ProductName       : Microsoft Windows Operating System

--- C2 servers ---
  208.105.226.235
  203.131.222.102

--- Decoded obfuscated APIs (111) ---
  VirtualFree
  VirtualAlloc
  ...
```

The script does no detonation, makes no network requests, and runs in seconds against a sample of any size in this family. It is a pure static pass over the PE bytes -- safe to run inside any analyst workstation without sandboxing.

---

## Prior Art and Further Reading

Destover and the SPE attack are among the most-analyzed pieces of malware in the public record. The write-up above relies extensively on prior research and adds little technical novelty -- the goal here is to walk through the binary in a way that an analyst can follow end-to-end without having to also have read every published source. The key references:

- **[Securelist: Destover malware now digitally signed by Sony certificates (2014)](https://securelist.com/destover-malware-now-digitally-signed-by-sony-certificates/68073/)**: Kaspersky GReAT's first published note on the signed variant, including the C2 IP attribution and the "this is not the wild attack sample, but it is functionally identical" caveat.
- **[Securelist: Sony/Destover, mystery North Korean actor's destructive and past network activity (2014)](https://securelist.com/destover/67985/)**: broader pre-attack timeline, links the family to the DarkSeoul cluster, walks through the campaign behavior of earlier Wiper.A samples.
- **[Damballa: secrets behind the Destover malware (2015)](https://securityaffairs.com/42194/malware/destover-malware-analysis.html)**: analysis of the post-attack toolkit including `setMFT` and `afset` anti-forensics utilities that paired with the binary covered here.
- **[ThreatPost: Details Emerge on Sony Wiper Malware Destover (2014)](https://threatpost.com/details-emerge-on-sony-wiper-malware-destover/109727/)**: early write-up of the wiper component and EldoS RawDisk driver dependency.
- **[APTnotes: From Seoul to Sony (kbandla)](https://github.com/kbandla/APTnotes/issues/260)**: DarkSeoul / Lazarus history and the wiper-malware lineage from 2013 forward.
- **[Bank InfoSecurity: Destover Taps Stolen Sony Certificate (2014)](https://www.bankinfosecurity.com/destover-taps-stolen-sony-certificate-a-7660)**: the contemporary debate over whether the signed variant was a researcher's "joke" or part of the actual attacker's toolkit.

### External corroboration

The technical claims in this post line up with a long tail of independent observations against this exact SHA256:

- **Florian Roth's Valhalla / THOR APT Scanner** has continuously produced detection coverage for this sample under Lazarus / Destover-named rules since at least 2017 (`Destover_Nov17_signed_sample`, `Destover_Malware_APT`, `APT_MAL_NK_Lazarus_Apr20_1`, `MAL_Trojan_Destover_Nov22`). Each of those rule generations was published years apart by a separate author, on independent string-and-structural sets, and all four match the same hash.
- **FileScan.IO** and **Hybrid Analysis** sandbox runs from 2017 onwards consistently report the same two C2 endpoints (`203.131.222.102:443`, `208.105.226.235:443`) and the same dot-space-obfuscated import surface that the static walkthrough above documents.
- The signing chain `Sony Pictures Entertainment Inc.` to `DigiCert Assured ID Code Signing CA-1` is observable in every published research artifact carrying this hash, and the certificate's revocation status (revoked December 2014) is publicly verifiable through DigiCert's CRL.

The external history is not the source of the analysis above; everything in the post was extracted from the binary on the workbench. The corroboration is included so a defender can validate any single claim against multiple independent vantage points before adopting it operationally.

### What this analysis adds

Given the weight of prior art, it is worth being explicit about what is incremental here:

- A **complete decoded list of all 111 obfuscated API names** in this build, including the `RegisterServiceCtrlHandlerW` / `StartServiceCtrlDispatcherW` pair that confirms the binary supports a service-mode entry path beyond the GUI default subsystem.
- A **clean disassembly walkthrough of the 10-entry C2 server table** initialization, including the five operator-tunable knobs (`port`, `sleep`, `retry_max`, `tick_seed`, `state`) at fixed addresses in the .data section.
- An **annotated breakdown of the date-trigger gate at `fcn.00406917`** showing how the constants at `0x004140xx` are the activation deadline, and explaining why this binary is a *latent* wiper-stager rather than a guaranteed wiper.
- A **Python static config extractor** that pulls IPs, signer, version-info, and decoded API list in a single pass with no detonation.
- **Two paired YARA rules** -- a behavior-fingerprint rule and a stolen-certificate rule -- both validated green against the sample.
- An **observation about the `cmd.exe` shell-exec format string** being split with two `%s` placeholders specifically to defeat substring-based detection on `cmd.exe /c`, which is a small but real defensive primitive worth noting.

---

## Conclusion

The Destover backdoor is, on a strict technical-novelty axis, not impressive. It uses a hard-coded list of two C2 IPs with no fallback, a uniform sixty-second sleep with no jitter, a dot-space character-substitution obfuscation that falls to a four-character regex, and a hand-rolled service installation that any modern EDR catches on the first call to `CreateServiceW`. The binary itself is a journeyman's RAT.

What made it a successful tool of impact in 2014 was the operational context around it: a stolen code-signing certificate from the victim's own organization, a disciplined attacker who staged the implant for months before activation, a destructive deadline aligned with a public news cycle, and a defensive industry that had not yet adapted to treat stolen-from-victim signatures as a primary indicator-of-compromise rather than a trust signal.

The lesson is not that Destover is hard to detect -- it is not, today -- but that the technical floor for an actor with operational discipline and a single high-value credential is much lower than the technical floor for an actor without those advantages. The stolen-certificate primitive is the entire reason this binary mattered. Strip the signature, and the result is a 2014-vintage tier-3 RAT that any current-generation static engine flags inside a hundred milliseconds. Add the signature, and the same RAT carried a Fortune 500 victim's network for weeks before anyone noticed.

The samples that taught the industry to revoke faster, to validate revocation more strictly, and to treat code-signing as a hardened operational asset rather than a developer convenience -- those samples started here.
