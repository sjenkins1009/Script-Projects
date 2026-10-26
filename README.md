# Script Projects

PowerShell scripts for endpoint remediation.

## Remediate-OracleJRE.ps1

Remediates Microsoft Defender Vulnerability Management "vulnerabilities in Oracle Jre" findings by upgrading Oracle JRE 8 to the newest release while staying on Java 8.

- Looks up the newest Java 8 release (including build number) on java.com and downloads the offline installers from Oracle, verifying the Oracle signature.
- Upgrades only the architectures already present (x86 and/or x64), then silently uninstalls older Java 8 versions and deletes leftover `jre1.8.0_xxx` folders.
- Leaves end-of-life Java majors (6, 7, 9, 10) and JDKs alone and reports them.
- Waits for other installs in progress, retries once on exit code 1618, and stops any install step after a timeout.
- Runs silently and relaunches in 64-bit PowerShell from 32-bit RMM agents.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remediate-OracleJRE.ps1          # remediate
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remediate-OracleJRE.ps1 -WhatIf  # dry run
```

Run as SYSTEM or an elevated admin. Exit codes: `0` compliant, `3010` compliant with reboot pending, `1` failure. Logs go to `%ProgramData%\JavaRemediation\`.

Oracle Java 8 updates after 8u202 are licensed under Oracle's terms, which require a subscription for commercial use.
