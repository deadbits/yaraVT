# Yara VirusTotal Commenter
You know you scan files with Yara anyways, why not give your findings back to the community?  
This script can scan a folder of samples against a provided Yara ruleset and optionally submit the matching Yara rule names to each files respective VirusTotal report as a comment.

**Important:** Use this script only with high-confidence Yara rules to avoid spamming VT with misleading comments

## Pre-Alpha
This code hasn't yet been tested in any real way. I would not recommend using it :)

### Usage
```
$ python yara_vt.py --help                                                                                                                                                 (master)
usage: yara_vt.py [-h] -r RULES -s SAMPLES [-k KEY] -c

Scan directory with Yara and submit matches to VirusTotal samples as comments

optional arguments:
  -h, --help            show this help message and exit

Yara:
  -r RULES, --rules RULES
                        yara rules directory
  -s SAMPLES, ---samples SAMPLES
                        samples directory to scan

VirusTotal:
  -k KEY, --key KEY     virustotal API key
  -c, --comment         submit virustotal comments
```