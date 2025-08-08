# IP Lookup Utility

## Install python packages
```
pip3 install -r requirements.txt
```

## Setup IP Info API Token
- Signup for free API token: https://ipinfo.io/signup
- After retrieving the token, export token to environment:
```
export IPINFO_TOKEN="<TOKEN>"
```

## Setup ASN DB
- After install pyasn, run the following commands under the script's directory:
```
pyasn_util_download.py --latest --filename ./data/pyasnrib.bz2
pyasn_util_convert.py --single ./data/pyasnrib.bz2 asndb.dat
pyasn_util_asnames.py -o ./data/datasnames.json
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
