# PowerShell-Analyzer
A simple scanner for PowerShell scripts to detect malicious capablities.

This program is a tool written in Python to scan a given file for high fidelity PowerShell strings commonly abused by threat actors in malicious ps1 scripts. It seeks out indicators from 4 main categories: 
* Obfuscation/Encoding - base64, Bitwise XOR, Hex
* Evasion/Bypass - Evasion of execution policies, Windows Defender alterations, AMSI bypass
* FileSystem - Creation and deletion of files
* Networking - Connect, downloads and web request capabilities

Added MD5sum functionalities for file input.
Currently still working to expand the indicators sets in the json library. Feel free to contribute!

## Program Usage

```
python Powershell_Analyzer.py -f <FILE>
```
![image](https://github.com/davincico/PowerShell-Analyzer/assets/50984080/c7d79e62-339e-42e1-b31b-d0fe98b73461)

## Pending Improvements & Ideas
1. Improve the json database for high fidelity commonly abused PowerShell strings found in malware/malicious scripts
2. Enrichment using VirusTotal on the MD5 hash extracted for the file
3. Serve as a module for a more comprehensive all-in-one malware/file analyzer
