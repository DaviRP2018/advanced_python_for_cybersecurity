import socket

import dns
import dns.resolver

dictionary = []
d = "subdomains.txt"
with open(d, "r") as f:
    dictionary = f.read().splitlines()

hosts = {}


def reverse_dns(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]] + result[1]
    except socket.herror:
        return []


def dns_request(sub, domain):
    global hosts
    hostname = sub + domain
    try:
        result = dns.resolver.resolve(hostname)
        if result:
            for answer in result:
                ip = answer.to_text()
                hostnames = reverse_dns(ip)
                subs = [sub]
                for hostname in hostnames:
                    if hostname.endswith(domain):
                        s = hostname.rstrip(domain)
                        subs.append(s)
                if ip in hosts:
                    s = hosts[ip]["subs"]
                    hosts[ip] = list(dict.fromkeys(s + subs))
                else:
                    hosts[ip] = list(dict.fromkeys(subs))
    except:
        return


def subdomain_search(domain, nums):
    for word in dictionary:
        dns_request(word, domain)
        if nums:
            for i in range(0, 10):
                dns_request(word + str(i), domain)


def dns_search(domain, nums):
    subdomain_search(domain, nums)
    return hosts


"""domain = ".google.com"
hosts = DNSSearch(domain,True)
for ip in hosts:
    print(ip,hosts[ip])"""
