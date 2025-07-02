import os
import sys
import re
import ipaddress

# Terminal color codes
RESET = "\033[0m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"

# Auto-install required modules
try:
    import requests
except ImportError:
    print(f"{YELLOW}[*] Installing 'requests'...{RESET}")
    os.system("pip install requests")
    import requests

def check_private_public(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            print(f"\n{MAGENTA}[+] IP Type: Private (Local Network IP){RESET}")
        else:
            print(f"\n{GREEN}[+] IP Type: Public (Internet Facing IP){RESET}")
    except ValueError:
        print(f"{RED}[!] Invalid IP address format.{RESET}")

def geo_lookup(ip):
    print(f"\n{CYAN}--- IP Geolocation (ipinfo.io) ---{RESET}")
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"{YELLOW}IP Address   : {data.get('ip', 'N/A')}{RESET}")
            print(f"{YELLOW}City         : {data.get('city', 'N/A')}{RESET}")
            print(f"{YELLOW}Region       : {data.get('region', 'N/A')}{RESET}")
            print(f"{YELLOW}Country      : {data.get('country', 'N/A')}{RESET}")
            print(f"{YELLOW}Location     : {data.get('loc', 'N/A')}{RESET}")
            print(f"{YELLOW}Organization : {data.get('org', 'N/A')}{RESET}")
            print(f"{YELLOW}Timezone     : {data.get('timezone', 'N/A')}{RESET}")
        else:
            print(f"{RED}[!] Failed to get GeoIP data.{RESET}")
    except Exception as e:
        print(f"{RED}[!] GeoIP Error: {e}{RESET}")

def whois_lookup(ip):
    print(f"\n{CYAN}--- WHOIS Lookup (rdap.org) ---{RESET}")
    try:
        url = f"https://rdap.org/ip/{ip}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            network = data.get('name', 'N/A')
            country = data.get('country', 'N/A')
            asn = data.get('handle', 'N/A')
            asn_desc = 'N/A'

            remarks = data.get('remarks')
            if remarks:
                for remark in remarks:
                    if 'description' in remark:
                        asn_desc = remark['description'][0]
                        break

            print(f"{YELLOW}Network Name : {network}{RESET}")
            print(f"{YELLOW}Country      : {country}{RESET}")
            print(f"{YELLOW}ASN          : {asn}{RESET}")
            print(f"{YELLOW}ASN Org      : {asn_desc}{RESET}")

            return asn_desc
        else:
            print(f"{RED}[!] Failed to fetch WHOIS info from RDAP API{RESET}")
            return None
    except Exception as e:
        print(f"{RED}[!] WHOIS API Error: {e}{RESET}")
        return None

def detect_isp_type(asn_desc):
    print(f"\n{CYAN}--- ISP Type Detection ---{RESET}")
    if asn_desc:
        mobile_keywords = ["mobile", "cellular", "wireless", "Jio", "Airtel", "Vodafone", "Idea", "Vi", "Reliance"]
        broadband_keywords = ["broadband", "fiber", "fibernet", "DSL", "BSNL", "ACT", "Hathway", "Spectra"]

        lower_asn = asn_desc.lower()

        if any(keyword.lower() in lower_asn for keyword in mobile_keywords):
            print(f"{GREEN}[+] ISP Type: Mobile Network{RESET}")
            return "Mobile"
        elif any(keyword.lower() in lower_asn for keyword in broadband_keywords):
            print(f"{GREEN}[+] ISP Type: Broadband / Fixed Line{RESET}")
            return "Broadband"
        else:
            print(f"{MAGENTA}[+] ISP Type: Unknown / Other{RESET}")
            return "Unknown"
    else:
        print(f"{RED}[!] ASN Info missing for ISP type detection.{RESET}")
        return "Unknown"

def device_type_guess(isp_type):
    print(f"\n{CYAN}--- Device Type Guess ---{RESET}")
    if isp_type == "Mobile":
        print(f"{MAGENTA}[+] Possible Device: Smartphone / Mobile Device{RESET}")
    elif isp_type == "Broadband":
        print(f"{MAGENTA}[+] Possible Device: Laptop / PC / Router{RESET}")
    else:
        print(f"{MAGENTA}[+] Possible Device: Cannot Determine (Unknown Network Type){RESET}")

def main():
    print(f"\n{CYAN}========== IP Information Tool =========={RESET}")
    print(f"{BLUE}Enter target IP address:{RESET} ", end="")
    ip = input().strip()
    if not ip:
        print(f"{RED}[!] No IP entered. Exiting.{RESET}")
        sys.exit()

    check_private_public(ip)
    geo_lookup(ip)
    asn_desc = whois_lookup(ip)
    isp_type = detect_isp_type(asn_desc)
    device_type_guess(isp_type)
    print(f"\n{CYAN}========== Scan Complete =========={RESET}\n")

if __name__ == "__main__":
    main()
