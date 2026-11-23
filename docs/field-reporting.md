# Observed Use, Reporting, and Process Hollowing

This guide separates confirmed field observations from malware sample analysis,
proofs of concept, and detection research. Public Linux reporting often uses
"injection" for several mechanisms that have different lifecycles and evidence.
The summary reflects sources available on 2026-11-23.

## Evidence labels

- **Field telemetry**: a vendor reports endpoint or incident observations, not
  only files submitted to a sample exchange.
- **Named malware analysis**: researchers analyzed a real malware family or
  rootkit, but may not know its victim scope or deployment history.
- **Research or PoC**: the mechanism is demonstrated and viable, but the source
  does not establish adversary deployment.
- **Detection content**: a rule or analytic proves that defenders consider the
  behavior useful to monitor; it does not prove prevalence.

## What public reporting supports

| Source | Reported behavior | Classification | What it proves |
| --- | --- | --- | --- |
| [Elastic Global Threat Report 2025](https://www.elastic.co/pdf/elastic-global-threat-report-2025) | Linux telemetry includes `LD_PRELOAD` abuse; shared-object rootkits that modify preload configuration are one of the principal rootkit categories described | Field telemetry | Loader hijacking and user-space rootkits are operationally relevant |
| [OrBit analysis](https://research.intezer.com/blog/2022/07/orbit-new-undetected-linux-threat/) and [2026 follow-up](https://intezer.com/blog/orbit-returns) | Loader configuration and a patched dynamic loader cause a malicious shared object to enter processes; later reporting associates OrBit use with BLOCKADE SPIDER | Named malware plus campaign reporting | Shared-object loading and API hooking are used beyond laboratory PoCs |
| [PUMAKIT analysis](https://security-labs.elastic.co/security-labs/declawing-pumakit) | Memory-resident executables, an LKM, and an embedded Kitsune shared object with `LD_PRELOAD` behavior | Named malware analysis | `memfd` execution and loader-based user-space hooking occur in real rootkit tooling, but are not the same as remote-process memory injection |
| [FontOnLake](https://www.welivesecurity.com/2021/10/07/fontonlake-previously-unknown-malware-family-targeting-linux/) | Trojanized standard utilities load additional components and collect data; ESET reports signs of targeted use | Named malware analysis with targeted-use indicators | Binary replacement and module loading are used in Linux operations, but should not be mislabeled as live-process injection |
| [MITRE T1055.008](https://attack.mitre.org/techniques/T1055/008/) | PACEMAKER can use ptrace to attach to a target and read memory | ATT&CK procedure reporting | Ptrace access is reported, but the cited procedure is memory reading, not proof of code injection |
| [Virus Bulletin shared-object injection research](https://virusbulletin.com/conference/vb2024/abstracts/so-looks-suspicious-leveraging-process-memory-and-kernelusermode-probes-detect-shared-object-injection-scale-linux/) | Covers `DT_NEEDED`, `LD_PRELOAD`, direct loader calls, reflective loading, hollowing, and memory-based detection | Detection research | These are defensible detection categories; prevalence must come from separate incident evidence |

The strongest public evidence is for dynamic-loader hijacking, shared-object
rootkits, binary tampering, and memory-backed execution. Public named reporting
for low-level `PTRACE_POKETEXT`, `/proc/<pid>/mem`, or
`process_vm_writev` execution chains is much thinner. Those primitives are well
represented in research and red-team PoCs, but a PoC or a detection rule should
not be reported as confirmed in-the-wild use.

## Process hollowing on Linux

The canonical Windows workflow creates a suspended process, unmaps its image,
writes a replacement image, changes thread context, and resumes it. MITRE's
[T1055.012](https://attack.mitre.org/techniques/T1055/012/) procedures and
detection strategy are Windows-oriented.

Linux research uses the term more broadly. The
[`linux-prinj` hollowing example](https://github.com/antifob/linux-prinj/tree/main/04-hollowing)
does the following:

1. The child requests tracing with `PTRACE_TRACEME`.
2. The child executes a selected program.
3. The parent waits for the post-exec stop and reads RIP.
4. The parent replaces code at RIP with `PTRACE_POKETEXT`.
5. The process resumes under its original identity and mappings.

That is a valid hollowing analogue, but **entry-point stomping** is the more
precise description because it does not unmap and rebuild the full ELF image.
The repository's [`process_hollowing`](../process_hollowing/) lab implements
this narrower pattern with a controlled static child and a benign `exit(42)`
marker.

A fuller Linux hollowing experiment would need to replace executable `PT_LOAD`
segments, reconcile page protections and relocations, handle the interpreter
and auxiliary vector, repair register and stack state, and define what remains
of the original file-backed image. That is substantially different from merely
changing the process name.

## Common classification mistakes

| Observed behavior | Better classification |
| --- | --- |
| `LD_PRELOAD` or `/etc/ld.so.preload` loads a module at process start | Dynamic linker hijacking or loader injection |
| `memfd_create` followed by `fexecve` or `execveat` | Memory-backed or fileless execution |
| `comm`, `argv`, or process title changes | Process masquerading |
| Ptrace reads another process's memory | Process access or credential access, not injection by itself |
| A remote write changes ordinary data | Cross-process memory modification; execution is not yet established |
| Initial code bytes change after an exec stop | Entry-point stomping or a Linux hollowing analogue |
| Most original ELF mappings are replaced and execution resumes under the old identity | Stronger process-hollowing claim, if mapping evidence supports it |

## How to report a sighting

Record enough evidence to reconstruct the chain:

1. Source and target PIDs, ancestry, credentials, namespaces, and executable
   identities.
2. Access primitive and exact request, syscall, or procfs path.
3. Destination address and its mapping permissions before the write.
4. Whether bytes, pointers, registers, or complete mappings changed.
5. The event that transferred execution.
6. New modules, anonymous executable mappings, deleted files, or memfd names.
7. State restoration, target survival, and any mismatch between mapped bytes
   and the backing executable.
8. Evidence class: field telemetry, malware analysis, PoC reproduction, or
   detection-only hypothesis.

This keeps a technically valid detection from becoming an unsupported claim
about adversary prevalence.
