# Python Standard Packages
import re
import os
import sys
import json

# External Packages
import argparse
import requests
import ipaddress

# IP Lookup Specific Packages
import pyasn
from ipwhois import IPWhois


# Print colors
G = "\033[92m"
C = "\033[36m"
Y = "\033[93m"
R = "\033[91m"
B = "\033[1m"
E = "\033[00m"


# Directory setup
basedir = os.path.abspath(os.path.dirname(__file__))
data_path = os.path.join(basedir, "data")


if not os.path.exists(data_path):
    print(f"{Y}{B}[!] ASN Database not found. Installing and downloading necessary files.{E}")
    os.mkdir(data_path)
    contents = os.listdir(data_path)
    if not contents:
        os.system("./setup_asn_db.sh")
        print(f"{G}{B}[*] Download complete. Please rerun script.{E}")
        sys.exit()


def ip_whois_lookup(ipaddr):
    print(f"\n{G}{B}[*] IP Lookup using WHOIS RDAP...{E}")
    lookup = IPWhois(ipaddr)
    resp = lookup.lookup_rdap()
    if resp:
        return {
            "name": resp["network"]["name"],
            "asn": resp["asn"],
            "asn_cidr": resp["asn_cidr"],
            "net_cidr": resp["network"]["cidr"],
            "net_start_address": resp["network"]["start_address"],
            "net_end_address": resp["network"]["end_address"],
            "network": resp["network"]["handle"],
            "status": ", ".join(resp["network"]["status"]),
            "country": resp["asn_country_code"],
            "description": resp["asn_description"],
        }
    

def ip_info_lookup(ipaddr):
    print(f"\n{G}{B}[*] IP Lookup using IP Info...{E}")
    IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN")
    resp = requests.get(f"https://api.ipinfo.io/lite/{ipaddr}?token={IPINFO_TOKEN}").json()
    return resp


def ip_asn_info_lookup(ipaddr):
    print(f"\n{G}{B}[*] ASN Lookup using MRT/RIB BGP archive...{E}")
    asndb = pyasn.pyasn('./data/asndb.dat')
    resp = asndb.lookup(ipaddr)
    as_number = str(resp[0])
    as_prefix = resp[1]

    with open("./data/asnames.json", "r") as f:
        asn_names = json.load(f)
        as_name = asn_names[as_number]

    return {
        "as_name": as_name,
        "as_number": as_number,
        "as_prefix": as_prefix
    }


def asn_info_lookup_all_prefix(asn):
    asndb = pyasn.pyasn('./data/asndb.dat')
    as_prefixes = asndb.get_as_prefixes(asn)
    as_size = asndb.get_as_size(asn)

    with open("./data/asnames.json", "r") as f:
        asn_names = json.load(f)
        as_name = asn_names[asn]

    return {
        "as_name": as_name,
        "as_number": as_number,
        "as_size": as_size,
        "as_prefixes": as_prefixes
    }


def asn_info_lookup_prefix(asn, target_subnet):
    asndb = pyasn.pyasn('./data/asndb.dat')
    as_prefixes = asndb.get_as_prefixes(asn)
    as_size = asndb.get_as_size(asn)

    with open("./data/asnames.json", "r") as f:
        asn_names = json.load(f)
        as_name = asn_names[asn]

    prefixes = []
    for prefix in as_prefixes:
        if subnet_checker(target_subnet, prefix):
            prefixes.append(prefix)

    return {
        "as_name": as_name,
        "as_number": as_number,
        "as_size": as_size,
        "prefixes": prefixes
    }


def subnet_checker(ipaddr, target_cidr):
    address = ipaddress.IPv4Network(ipaddr)
    net_cidr = ipaddress.IPv4Network(target_cidr)

    if address.subnet_of(net_cidr):
        return True
    return False


def validate_ip_address(ipaddr):
    if re.search(r"^((1?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.?){4}(/[0-3][0-9])?$", ipaddr):
        return True
    return False


def dict_printer(dict_data):
    for key, value in dict_data.items():
        print(f"{C}{key}{E}: {value}")


def vt_get_ip_address_info(ipaddr):
    result = {}
    VT_TOKEN = os.environ.get("VT_TOKEN")
    headers = {"X-Apikey": VT_TOKEN}

    resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ipaddr}", headers=headers)

    if resp.ok:
        data = resp.json()["data"]["attributes"]
        analysis = data["last_analysis_stats"]
        votes = data["last_analysis_results"]
        mal_votes = [vote for vote in votes if votes[vote]["category"] in ("malicious", "suspicious")]
        result["analysis"] = analysis
        result["malicious_vendor_verdicts"] = mal_votes

    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP Lookup Utility. Retrieves IP Info, ASN Info, and WHOIS Info.")
    parser.add_argument("--ip-addr", help="IPv4 address. Note: CIDR is not accepted.")
    parser.add_argument("--as-number", help="Autonomous System Number. Note: CIDR is not accepted.")
    parser.add_argument("--target-subnet", help="Target IP address to look for from AS prefixes.")
    args = parser.parse_args()

    ip = args.ip_addr
    as_number = args.as_number
    target_subnet = args.target_subnet

    if ip:
        if validate_ip_address(ip):
            ip = ip.split("/")[0]
            print(f"{G}{B}[*] Looking up information for IP Address {ip} [*]")

            ip_whois_resp = ip_whois_lookup(ipaddr=ip)
            dict_printer(ip_whois_resp)

            ip_info_resp = ip_info_lookup(ipaddr=ip)
            dict_printer(ip_info_resp)

            ip_asn_info_resp = ip_asn_info_lookup(ipaddr=ip)
            dict_printer(ip_asn_info_resp)

            vt_result = vt_get_ip_address_info(ipaddr=ip)
            analysis = vt_result["analysis"]
            print(f"\n{G}{B}[*] Virus Total Info...{E}")
            print(f"{C}Analysis:{E}")
            for key, value in analysis.items():
                if value != 0:
                    print(f"{C}{key}: {value}")

            if vt_result["malicious_vendor_verdicts"]:
                print(f"\n{C}Malicious / Suspicious Vendor Verdict:{E}")
                print(", ".join(vt_result["malicious_vendor_verdicts"]))

        else:
            print("IP address is invalid!")

    elif as_number:
        if target_subnet:
            if validate_ip_address(target_subnet):
                as_number = as_number.lstrip("AS")
                asn_info_resp = asn_info_lookup_prefix(asn=as_number, target_subnet=target_subnet)
                dict_printer(asn_info_resp)
            else:
                        print("IP address is invalid!")
        else:
            as_number = as_number.lstrip("AS")
            asn_info_resp = asn_info_lookup_all_prefix(asn=as_number)
            dict_printer(asn_info_resp)
