import numpy as np
import requests
from urllib.parse import urlparse
import shutil
import ipaddress
import os
import re
import tempfile
import subprocess
from pathlib import Path

# yoinked from the bitwire guy
# https://github.com/bitwire-it/ipblocklist
# he does good work but my firewall cries about trying to load a 50MB file
# so working with as many individual sources as possible
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')

def parse_network_safe(line: str):
    """
    Safely parses a line into an ip_network object.
    1. Direct ip_network parse (handles bare IPs and CIDRs).
    2. URL parse — extracts IP from hostname (e.g. http://1.2.3.4/malware.exe).
    3. Regex fallback — first IPv4 in pipe-delimited lines (e.g. "ASN | 1.2.3.4 | Date").
    """
    line = line.strip()
    if not line:
        return False
    
    # 1. Direct Parsing — handles clean IPs (bare or CIDR)
    try:
        return ipaddress.ip_network(line, strict=False)
    except ValueError:
        pass

    # 2. Handle URLs (e.g. http://1.2.3.4/malware.exe)
    # This extracts the IP '1.2.3.4' from the URL.
    if '://' in line:
        try:
            parsed = urlparse(line)
            netloc = parsed.netloc
            
            # Cleanup brackets for IPv6 [::1]
            if netloc.startswith('[') and ']' in netloc:
                netloc = netloc.split(']')[0].strip('[')
            # Cleanup Port for IPv4 1.2.3.4:80
            elif ':' in netloc:
                # Be careful with IPv6 literals without brackets (rare in URLs but possible in raw data)
                # If it looks like IPv4 (3 dots), assume colon is port
                if netloc.count('.') == 3:
                    netloc = netloc.split(':')[0]
            
            addr = ipaddress.ip_address(netloc)
            return ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            pass # Domain name URLs will fail here, which is expected

    # 3. Regex Fallback (e.g. "ASN | 1.2.3.4 | Date")
    # Finds the first valid IPv4 string in the line
    match = IPV4_REGEX.search(line)
    if match:
        candidate = match.group(0)
        try:
            return ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            pass

    return False

def process_files(real_dir, filenames):
    print(str(filenames))
    # order by size so we check the largest/least unique one last
    sorted_filenames = sorted(filenames,
                        key =  lambda x: os.stat
                       (os.path.join(x)).st_size)

    networks = set()

    for filename in sorted_filenames:
        skipped = 0
        current_file_networks = set()
        print("Opening " + Path(filename).name + " (File size " + str(os.path.getsize(filename)) + " bytes)")
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                parsed_line = parse_network_safe(line.strip().split(" ", 1)[0])
                if parsed_line is not False:
                    network = (int(parsed_line.network_address), parsed_line.prefixlen)
                    if network not in networks:
                        current_file_networks.add(network)
                        networks.add(network)
                    else:
                        skipped += 1

        print("Found " + str(len(current_file_networks)) + " unique networks, " + str(skipped) + " duplicates")
        with open(real_dir / 'processed' / Path(filename).name, "w") as newfile:
            for network in current_file_networks:
                newfile.write(str(ipaddress.ip_network((network[0], network[1]))) + "\n")

def main() -> None:

    # so we can save files to our real path later
    real_dir = Path.cwd()

    with tempfile.TemporaryDirectory() as temp_dir:
        filepaths = []

        # get files from git repos
        # name paired with url and then the files we care about
        repos = {
            'firehol-mirror' : {
                'url' : 'https://github.com/borestad/firehol-mirror.git',
                'files' : [
                    'blocklist_de.ipset', 
                    'stopforumspam_1d.ipset', 
                    'spamhaus_drop.netset',
                    'php_spammers_1d.ipset',
                    'php_harvesters_1d.ipset',
                    'php_dictionary_1d.ipset',
                    'greensnow.ipset',
                    'dshield.netset',
                    'ciarmy.ipset',
                    'bruteforceblocker.ipset',
                    'blocklist_net_ua.ipset']
            }
        }
        for name, data in repos.items():
            subprocess.run(
                ["git", "clone", "--depth", "1", data['url'], temp_dir + '/' + name],
                check=True
            )

            for filename in data['files']:
                filepaths.append(temp_dir + '/' + name + '/' + filename)

        # Individual files
        single_files = {
            'abuseipdb_1d.txt' : 'https://github.com/borestad/blocklist-abuseipdb/raw/refs/heads/main/abuseipdb-s100-1d.ipv4',
            'blackmirror_ipv4.txt' : 'https://github.com/T145/black-mirror/releases/download/latest/BLOCK_IPV4.txt',
            'blackmirror_cidr4.txt' : 'https://github.com/T145/black-mirror/releases/download/latest/BLOCK_CIDR4.txt',
            'abuse_ch.txt' : 'https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds/raw/refs/heads/master/abuse-ch-ipblocklist.txt',
            'shadowwhisperer_threats.txt' : 'https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Threats',
            'shadowwhisperer_scanners.txt' : 'https://raw.githubusercontent.com/ShadowWhisperer/IPs/refs/heads/master/Lists/Scanners',
            'maliciousip_40k.txt' : 'https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/full-40k.txt',
            'maliciousip_subnets.txt' : 'https://raw.githubusercontent.com/romainmarcoux/malicious-ip/main/malicious_subnets.txt',
        }
        
        # fancy chunk downloading for big files
        for filename, url in single_files.items():
            with requests.get(url, stream=True) as r:
                r.raise_for_status()
                with open(temp_dir + '/' + filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): 
                        f.write(chunk)
                filepaths.append(temp_dir + '/' + filename)

        # process them
        process_files(real_dir, filepaths)
        print('Done processing!')
