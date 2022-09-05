import re

from PortScan import syn_scan, http_header_grab, banner_grab
from ShodanSearch import shodan_lookup

defaults = {
    "smtp": [25],
    "dns": [53],
    "ns": [53],
    "web": [80, 443],
    "www": [80, 443],
    "api": [80, 443],
    "ftp": [20, 21],
}


def service_id(ip, subs):
    records = []
    # Check Default Ports
    for sub in subs:
        s = sub.strip("0123456789")
        if s in defaults:
            records = [banner_record(ip, p) for p in defaults[s]]

    # Check Shodan
    if len(records) == 0:
        records = shodan_lookup(ip)
        for r in records:
            if not "product" in r:
                [r["product"], r["version"]] = parse_banner(r["banner"], r["port"])

    # Scan Common Ports
    if len(records) == 0:
        records = [banner_record(ip, p) for p in syn_scan(ip)]

    return records


def banner_record(ip, p):
    product = ""
    version = ""
    if p in [80, 443, 8080, 8443]:
        response = http_header_grab(ip, p)
        server = response.headers["Server"]
        [product, version] = parse_banner(server, p)
    else:
        banner = banner_grab(ip, p)
        if banner:
            [product, version] = parse_banner(banner, p)
    r = {"port": p, "product": product, "version": version}
    return r


def parse_banner(banner, port):
    product = ""
    version = ""
    if port in [80, 443, 8080, 8443]:
        if banner.startswith("HTTP"):
            match = re.search("Server: ([^\r\n]*)", banner)
            if match:
                server = match.groups()[0]
            else:
                server = ""
        else:
            server = banner
        vals = server.split(" ")[0].split("/")
        product = vals[0]
        version = vals[1] if len(vals) > 1 else ""
    else:
        x = re.search("([A-Za-z0-9]+)[/ _]([0-9]+([.][0-9]+)+)", banner)
        if x:
            product = x.groups()[0]
            version = x.groups()[1]
        else:
            x = re.findall("([a-z0-9]*((smtp)|(ftp))[a-z0-9]*)", banner.lower())
            if x:
                for y in x:
                    if y[0] != "esmtp":
                        product = y[0]
                        break
    return [product, version]


"""records = serviceID("3.20.135.129","")
for r in records:
    print(r)"""
