import os
import sys
import re
import ipaddress

# Auto-install required modules
try:
    import requests
except ImportError:
    print("[*] Installing 'requests' module...")
    os.system("pip install requests")
    import requests

try:
    from ipwhois import IPWhois
except ImportError:
    print("[*] Installing 'ipwhois' module...")
    os.system("pip install ipwhois")
    from ipwhois import IPWhois

def check_private_public(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            print("\n[+] IP Type: Private (Local Network IP)")
        else:
            print("\n[+] IP Type: Public (Internet Facing IP)")
    except ValueError:
        print("[!] Invalid IP address format.")

def geo_lookup(ip):
    print("\n--- IP Geolocation (ipinfo.io) ---")
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"IP Address   : {data.get('ip', 'N/A')}")
            print(f"City         : {data.get('city', 'N/A')}")
            print(f"Region       : {data.get('region', 'N/A')}")
            print(f"Country      : {data.get('country', 'N/A')}")
            print(f"Location     : {data.get('loc', 'N/A')}")
            print(f"Organization : {data.get('org', 'N/A')}")
            print(f"Timezone     : {data.get('timezone', 'N/A')}")
        else:
            print("[!] Failed to get GeoIP data.")
    except Exception as e:
        print(f"[!] GeoIP Error: {e}")

def whois_lookup(ip):
    print("\n--- WHOIS Lookup ---")
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        print(f"Network Name : {results['network']['name']}")
        print(f"Country      : {results['network']['country']}")
        asn_desc = results.get('asn_description', 'N/A')
        print(f"ASN          : {results['asn']}")
        print(f"ASN Org      : {asn_desc}")
        return asn_desc
    except Exception as e:
        print(f"[!] WHOIS Lookup Error: {e}")
        return None

def detect_isp_type(asn_desc):
    print("\n--- ISP Type Detection ---")
    if asn_desc:
        mobile_keywords = ["mobile", "cellular", "wireless", "Jio", "Airtel", "Vodafone", "Idea", "Vi", "Reliance"]
        broadband_keywords = ["broadband", "fiber", "fibernet", "DSL", "BSNL", "ACT", "Hathway", "Spectra"]

        lower_asn = asn_desc.lower()

        if any(keyword.lower() in lower_asn for keyword in mobile_keywords):
            print("[+] ISP Type: Mobile Network")
            return "Mobile"
        elif any(keyword.lower() in lower_asn for keyword in broadband_keywords):
            print("[+] ISP Type: Broadband / Fixed Line")
            return "Broadband"
        else:
            print("[+] ISP Type: Unknown / Other")
            return "Unknown"
    else:
        print("[!] ASN Info missing for ISP type detection.")
        return "Unknown"

def device_type_guess(isp_type):
    print("\n--- Device Type Guess ---")
    if isp_type == "Mobile":
        print("[+] Possible Device: Smartphone / Mobile Device")
    elif isp_type == "Broadband":
        print("[+] Possible Device: Laptop / PC / Router")
    else:
        print("[+] Possible Device: Cannot Determine (Unknown Network Type)")

def main():
    print("\n========== IP Information Tool ==========")
    ip = input("Enter target IP address: ").strip()
    if not ip:
        print("[!] No IP entered. Exiting.")
        sys.exit()

    check_private_public(ip)
    geo_lookup(ip)
    asn_desc = whois_lookup(ip)
    isp_type = detect_isp_type(asn_desc)
    device_type_guess(isp_type)
    print("\n========== Scan Complete ==========\n")

if __name__ == "__main__":
    main()