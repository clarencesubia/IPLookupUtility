# IP Lookup Utility

## Description
A command-line tool to retrieve IP address details, Autonomous System Number (ASN) information, and WHOIS data.
This tool can be used for network diagnostics, threat analysis, and general IP research with added functionality of virustotal IP analysis.

## Features
- IP Info Lookup – Get geolocation and network details for a given IPv4 address.
- ASN Info Lookup – Retrieve details for an Autonomous System Number, including announced prefixes.
- WHOIS Lookup – Fetch WHOIS registration data for IP addresses or ASN ranges.
- Subnet Target Search – Find whether a specific IP is covered by an ASN's announced prefixes.
- Check if IP has virustotal analysis and verdicts.

## Install python packages
```
pip3 install -r requirements.txt
```

## Setup IP Info API Token
- Signup for free API token: https://ipinfo.io/signup
- After retrieving the token, export token to environment (recommended to add to .bashrc):
```
export IPINFO_TOKEN="<TOKEN>"
```

## Setup ASN DB
- After installing pyasn, run the following commands under the script's directory:
```
pyasn_util_download.py --latest --filename ./data/pyasnrib.bz2
pyasn_util_convert.py --single ./data/pyasnrib.bz2 ./data/asndb.dat
pyasn_util_asnames.py -o ./data/asnames.json
```

## Setup VirusTotal
- Create API key from https://www.virustotal.com/gui/user/<username>/apikey
- Export to environment (recommended to add to .bashrc):
```
export VT_TOKEN="<TOKEN>"
```

## Usage
- Perform IP Lookup
```
python3 iplookuputil.py --ip-address <IP ADDRESS>
```

- Perform ASN Lookup
```
python3 iplookuputil.py --as-number 13335
```

- Check if IP belongs to ASN's prefixes
```
python ip_lookup.py --as-number 15169 --target-subnet 8.8.4.4
```

- Bulk IP checks using file containing IP addresses
```
python3 iplookuputil.py --ip-list ip_list.txt --vt
```

- Payload sample for IP List
```
192.10.10.1
192.10.10.2
192.10.10.3
192.10.10.4
192.10.10.5
```

## Notes
- Only IPv4 addresses are supported at the moment.
- CIDR notation is not accepted for --ip-addr or --as-number.
- Some lookups may take a few seconds depending on WHOIS server response times.
- Additional threat intelligence capabilities to be added in the future.

## Author
[Clarence R. Subia](https://github.com/clarencesubia/)

## Badges
[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/clarencesubia/IPLookupUtility)
[![Run in Cisco Cloud IDE](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-runable-icon.svg)](https://developer.cisco.com/codeexchange/devenv/clarencesubia/IPLookupUtility/)
