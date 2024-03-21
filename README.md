# PowerShell-Analyzer
A simple scanner for PowerShell scripts to detect malicious capablities.

This program is a tool written in Python to scan a given file for high fidelity PowerShell strings commonly abused by threat actors in malicious ps1 scripts. It seeks out indicators from 4 main categories: 
* Obfuscation/Encoding - base64, Bitwise XOR, Hex
* Evasion/Bypass - Evasion of execution policies, Windows Defender alterations, AMSI bypass
* FileSystem - Creation and deletion of files
* Networking - Connect, downloads and web request capabilities

Currently still working to expand the indicators sets in the json library.

## Program Usage

```
python Powershell_Analyzer.py -f <FILE>
```
![image](https://github.com/davincico/PowerShell-Analyzer/assets/50984080/5498d42f-5be6-4510-9c82-006041ece472)
