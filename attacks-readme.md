# Windows Security Guide: Top 50 Critical LOLBAS Techniques

 

## Overview

 

This comprehensive security guide documents the **top 50 most critical Living Off The Land Binaries, Scripts and Libraries (LOLBAS)** that attackers use to compromise Windows 11 systems. Each entry includes detailed attack techniques, real-world command examples, detection methods, and prevention strategies.

 

**Purpose**: This guide is designed for security professionals, system administrators, SOC analysts, and blue teams to understand how attackers abuse legitimate Windows binaries and how to defend against these techniques.

 

**Last Updated**: 2026-01-01

**Target Platform**: Windows 11 (Compatible with Windows 10, Server 2019/2022)

**Analysis Base**: 198 Windows 11-compatible LOLBAS entries

 

---

 

## Table of Contents

 

1. [Executive Summary](01-Executive-Summary.md) - Threat landscape overview, key findings, and quick reference

2. [Top 10 Critical LOLBAS](02-Top-10-Critical-LOLBAS.md) - Ultra-critical threats requiring immediate attention

3. [High Priority LOLBAS (Ranks 11-30)](03-High-Priority-LOLBAS.md) - Very high impact threats

4. [Medium Priority LOLBAS (Ranks 31-50)](04-Medium-Priority-LOLBAS.md) - Medium-high impact threats

5. [Detection Engineering Guide](05-Detection-Engineering.md) - Sigma, Elastic, and Splunk detection rules

6. [Hardening & Prevention Guide](06-Hardening-Guide.md) - WDAC policies, AppLocker, and mitigation strategies

 

---

 

## What is LOLBAS?

 

**Living Off The Land Binaries, Scripts and Libraries (LOLBAS)** are legitimate, Microsoft-signed executables, scripts, and DLLs that attackers abuse to:

 

- Execute malicious code without dropping custom malware

- Bypass application whitelisting (AppLocker/WDAC)

- Download payloads from the internet

- Hide files in Alternate Data Streams (ADS)

- Dump credentials from memory

- Establish persistence mechanisms

- Evade endpoint detection and response (EDR) tools

 

**Why This Matters**: Because these binaries are signed by Microsoft and are part of the operating system, they appear legitimate to security tools, making detection significantly more challenging.

 

---

 

## Threat Landscape

 

### MITRE ATT&CK Coverage

 

The top 50 LOLBAS techniques map to critical MITRE ATT&CK techniques:

 

| MITRE Technique | Count | Impact Level |

|-----------------|-------|--------------|

| **T1218** - Signed Binary Proxy Execution | 28 | CRITICAL |

| **T1105** - Ingress Tool Transfer (Download) | 18 | CRITICAL |

| **T1564.004** - NTFS Alternate Data Streams | 11 | HIGH |

| **T1127** - Trusted Developer Utilities Proxy | 6 | CRITICAL |

| **T1059** - Command and Scripting Interpreter | 7 | HIGH |

| **T1003** - OS Credential Dumping | 2 | CRITICAL |

| **T1055** - Process Injection | 1 | CRITICAL |

 

### Attack Categories

 

**Execute (30 binaries)** - Direct code execution capabilities

**AWL Bypass (19 binaries)** - Application whitelisting bypass

**Download (18 binaries)** - Payload delivery from remote sources

**ADS (11 binaries)** - Hiding artifacts in Alternate Data Streams

**Compile (6 binaries)** - On-the-fly code compilation

**Dump (2 binaries)** - Credential dumping capabilities

 

---

 

## Critical Threat Chains

 

Understanding how attackers chain these techniques is crucial for detection:

 

### Chain 1: Download → Execute → Hide

1. **Download**: `certutil.exe`, `bitsadmin.exe`, `msxsl.exe`

2. **Execute**: `rundll32.exe`, `mshta.exe`, `regsvr32.exe`

3. **Hide**: Use ADS with any ADS-capable binary

 

### Chain 2: AWL Bypass → Compile → Execute

1. **Bypass**: `msbuild.exe`, `installutil.exe`, `regasm.exe`

2. **Compile**: `csc.exe`, `jsc.exe` (inline C#/JavaScript)

3. **Execute**: Through trusted developer tools

 

### Chain 3: Proxy Execution via DLLs

1. **Loader**: `rundll32.exe` (always available)

2. **DLL Options**: `url.dll`, `advpack.dll`, `ieadvpack.dll`, `scrobj.dll`

3. **Result**: Execute arbitrary code through trusted Windows processes

 

### Chain 4: Script-Based Attacks

1. **Interpreters**: `mshta.exe`, `cscript.exe`, `wscript.exe`, `powershell.exe`

2. **Delivery**: Remote URLs or local files

3. **Hiding**: Alternate Data Streams support

 

---

 

## Top 10 Most Critical (Quick Reference)

 

| Rank | Binary | Categories | MITRE ATT&CK | Detection Rules |

|------|--------|-----------|--------------|-----------------|

| 1 | **Url.dll** | Execute | T1218.011 | 1 Sigma |

| 2 | **Bginfo.exe** | AWL Bypass, Execute | T1218 | 4 (incl. BlockRule) |

| 3 | **Msiexec.exe** | Execute | T1218.007 | 5 |

| 4 | **Msbuild.exe** | AWL Bypass, Execute | T1127.001 | 13 |

| 5 | **Rundll32.exe** | ADS, Execute | T1218.011, T1564.004 | 5 |

| 6 | **msxsl.exe** | ADS, AWL Bypass, Download, Execute | T1105, T1220, T1564 | 4 |

| 7 | **Wmic.exe** | ADS, Copy, Execute | T1105, T1218, T1564.004 | 16 |

| 8 | **Advpack.dll** | AWL Bypass, Execute | T1218.011 | 2 Sigma |

| 9 | **Mshta.exe** | ADS, Download, Execute | T1105, T1218.005 | 11 (incl. BlockRule) |

| 10 | **Ieadvpack.dll** | AWL Bypass, Execute | T1218.011 | 2 Sigma |

 

---

 

## Windows 11 Specific Considerations

 

### Deprecated but Still Present

- **Wmic.exe** - Officially deprecated in Windows 11 but still available for backward compatibility

  - Remains a valid attack vector through at least Win11 23H2

  - Microsoft recommends transitioning to PowerShell WMI cmdlets

 

### Newly Relevant Attack Vectors

- **Winget.exe** - Windows Package Manager (native in Windows 11)

- **Msedge.exe** - Microsoft Edge browser, replacing IE-based attacks

 

### Microsoft Blocking Recommendations

Per Microsoft WDAC (Windows Defender Application Control) recommendations:

1. **Mshta.exe** - High abuse potential, limited legitimate use cases

2. **Bginfo.exe** - SysInternals tool, often unnecessary in production

 

### Compatibility Notes

- All 50 selected binaries confirmed working on Windows 11

- Alternate Data Streams (ADS) techniques remain fully functional

- Some commands require specific Windows 11 versions (noted in detailed sections)

 

---

 

## How to Use This Guide

 

### For Security Operations Centers (SOC)

1. **Start** with the [Executive Summary](01-Executive-Summary.md) to understand the threat landscape

2. **Review** [Top 10 Critical LOLBAS](02-Top-10-Critical-LOLBAS.md) for immediate high-priority threats

3. **Implement** detection rules from [Detection Engineering Guide](05-Detection-Engineering.md)

4. **Monitor** your environment for IOCs and behavioral patterns described in each section

 

### For System Administrators

1. **Begin** with the [Hardening & Prevention Guide](06-Hardening-Guide.md)

2. **Configure** Windows Defender Application Control (WDAC) policies

3. **Deploy** AppLocker rules where applicable

4. **Establish** baseline monitoring for legitimate use of these binaries

 

### For Red Teams / Penetration Testers

1. **Understand** the techniques in Tiers 1-3

2. **Test** your organization's detection capabilities

3. **Document** gaps for blue team remediation

4. **Respect** authorization scope - only use on authorized systems

 

### For Incident Responders

1. **Reference** specific binary sections when investigating alerts

2. **Look** for the attack chains described in this guide

3. **Correlate** multiple LOLBAS usage patterns for sophisticated attacks

4. **Check** Alternate Data Streams for hidden payloads

 

---

 

## Detection Priorities

 

Based on analysis of 50 critical LOLBAS:

 

### Immediate Priority (Most Detection Rules)

1. **Wmic.exe** - 16 detection rules

2. **Msbuild.exe** - 13 detection rules

3. **Powershell.exe** - 15 detection rules

4. **Mshta.exe** - 11 detection rules

5. **Regsvr32.exe** - 11 detection rules

 

### High Abuse Potential

- **Rundll32.exe** + DLLs - Extremely versatile execution chain

- **Script Interpreters** - Mshta, Cscript, Wscript (difficult to block)

- **Developer Tools** - Msbuild, Csc, Jsc (compile and execute on-the-fly)

- **Download Tools** - Certutil, Bitsadmin, msxsl (initial payload delivery)

 

---

 

## Document Structure

 

Each LOLBAS entry in this guide includes:

 

### Binary Overview

- Full file paths

- Description and purpose

- Windows version compatibility

 

### Attack Techniques

- All command variants with real examples

- MITRE ATT&CK technique mappings

- Required privilege levels (User/Admin)

- Attack use cases and scenarios

 

### Detection Methods

- Sigma rules (community-driven detection)

- Elastic Detection Rules

- Splunk Security Content

- Behavioral IOCs

- Network indicators

 

### Prevention & Mitigation

- WDAC/AppLocker blocking strategies

- Attack Surface Reduction (ASR) rules

- Monitoring recommendations

- Legitimate use case considerations

 

### Real-World Context

- APT group usage

- Security researcher insights

- Reference links and acknowledgements

 

---

 

## Methodology

 

### Selection Criteria

Binaries were scored and ranked based on:

 

1. **Windows 11 Compatibility** (50 points + mandatory)

2. **MITRE Technique Priority** (80-100 points):

   - T1218 (Signed Binary Proxy): 100 points

   - T1105 (Download): 90 points

   - T1003 (Credential Dump): 95 points

   - T1127 (Trusted Dev Utilities): 85 points

3. **Attack Categories** (15-50 points):

   - Execute: 50 points

   - AWL Bypass: 45 points

   - Download: 40 points

4. **Attack Vectors**: Up to 30 points for multiple commands

5. **Detection Coverage**: Up to 30 points based on available rules

6. **Documentation**: Up to 30 points for research/resources

 

### Data Source

- **LOLBAS Project**: https://lolbas-project.github.io/

- **Total Binaries Analyzed**: 213

- **Windows 11 Compatible**: 198 (93%)

- **Top 50 Selection**: 25% of compatible binaries

- **Analysis Date**: 2026-01-01

 

---

 

## Quick Start Actions

 

### For Immediate Defense Improvements

 

1. **Deploy Sigma Rules** for Top 10 binaries (see Detection Engineering Guide)

2. **Enable WDAC** to block Mshta.exe and Bginfo.exe

3. **Monitor** rundll32.exe with unusual DLL parameters

4. **Baseline** legitimate msbuild.exe and csc.exe usage

5. **Alert** on certutil.exe, bitsadmin.exe downloading from internet

6. **Audit** Alternate Data Streams creation across file servers

 

### For Comprehensive Security Posture

 

1. **Read** all tier documentation (Tiers 1-3)

2. **Implement** detection rules for all 50 binaries

3. **Configure** AppLocker/WDAC according to Hardening Guide

4. **Train** SOC team on LOLBAS attack patterns

5. **Establish** threat hunting queries for attack chains

6. **Test** detection capabilities with red team exercises

 

---

 

## Limitations & Scope

 

### What This Guide Covers

- Top 50 most critical LOLBAS for Windows 11

- Attack techniques with command examples

- Detection and prevention strategies

- MITRE ATT&CK mappings

 

### What This Guide Does NOT Cover

- Binaries blocked/removed in Windows 11

- Honorable mentions (binaries not meeting all LOLBAS criteria)

- Windows Server 2025-specific techniques (limited documentation available)

- Zero-day techniques not yet documented in LOLBAS project

- Detailed malware analysis or specific APT campaign breakdowns

 

### Defensive Focus

This guide prioritizes **defensive security**:

- Understanding attacker techniques

- Implementing detection mechanisms

- Preventing abuse through hardening

- Responding to incidents effectively

 

---

 

## Additional Resources

 

### Official Resources

- **LOLBAS Project**: https://github.com/LOLBAS-Project/LOLBAS

- **MITRE ATT&CK**: https://attack.mitre.org/

- **Microsoft WDAC Documentation**: https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/

 

### Detection Rules

- **Sigma HQ**: https://github.com/SigmaHQ/sigma

- **Elastic Detection Rules**: https://github.com/elastic/detection-rules

- **Splunk Security Content**: https://github.com/splunk/security_content

 

### Community

- **LOLBAS Twitter**: Follow researchers in acknowledgements

- **MITRE ATT&CK Navigator**: Visualize technique coverage

 

---

 

## Contributing & Feedback

 

This guide is based on the LOLBAS project, which is community-driven. If you:

- Discover new techniques or variants

- Develop new detection rules

- Find errors or outdated information

 

Please contribute to the LOLBAS project at: https://github.com/LOLBAS-Project/LOLBAS

 

---

 

## Credits

 

**Analysis and Documentation**: Based on comprehensive analysis of LOLBAS Project YAML database

 

**LOLBAS Project Contributors**:

- Oddvar Moe (Primary Maintainer) - 86 entries

- LOLBAS Team - 12 entries

- Security Research Community - 100+ contributors

 

**Detection Rule Authors**: Sigma HQ, Elastic Security, Splunk, and independent security researchers

 

**Framework**: MITRE ATT&CK (https://attack.mitre.org/)

 

---

 

## License & Disclaimer

 

### Educational Purpose

This guide is provided for **defensive security, education, and authorized security testing only**.

 

### Prohibited Uses

- Unauthorized access to computer systems

- Malicious use of techniques described herein

- Violation of applicable laws and regulations

 

### Disclaimer

The techniques described in this guide exist in publicly available documentation (LOLBAS project). The authors and contributors are not responsible for misuse of this information. Always obtain proper authorization before testing security controls.

 

---

 

**Navigate to**: [Executive Summary →](01-Executive-Summary.md)
