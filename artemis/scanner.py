from dotenv import load_dotenv
import wappalyzer
import requests
import json
import os

load_dotenv()


class IPScanner(object):
    def __init__(self):
        self.WHOISXML_KEY = os.getenv("whoisxml_api_key")
        self.WHOIS_URL = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={self.WHOISXML_KEY}&domainName="
        self.DNSL_URL = f"https://www.whoisxmlapi.com/whoisserver/DNSService?apiKey={self.WHOISXML_KEY}&domainName="
        self.IPG_URL = f"https://ip-geolocation.whoisxmlapi.com/api/v1?apiKey={self.WHOISXML_KEY}&ipAddress="
        self.SDOMAIN_URL = f"https://reverse-dns.whoisxmlapi.com/api/v1"

    def whois_lookup(self, domain: str):
        headers = {
            "Accept": "application/json"
        }
        req = requests.get(f"{self.WHOIS_URL}{domain}&outputFormat=JSON", headers=headers)
        res = req.json()

        return res

    def dns_lookup(self, domain: str):
        headers = {
            "Accept": "application/json"
        }
        req = requests.get(f"{self.DNSL_URL}{domain}&outputFormat=JSON", headers=headers)
        res = req.json()

        return res

    def ipgeo_lookup(self, ip: str):
        headers = {
            "Accept": "application/json"
        }
        req = requests.get(f"{self.IPG_URL}{ip}&outputFormat=JSON", headers=headers)
        res = req.json()

        return res

    def subdomain_lookup(self, domain: str):
        headers = {
            "Accept": "application/json"
        }
        data = json.dumps({
            "apiKey": self.WHOISXML_KEY,
            "outputFormat": "JSON",
            "domains": {
                "include": [
                    domain
                ]
            }
        })
        req = requests.post(self.SDOMAIN_URL, headers=headers, data=data)

        res = req.json()

        return res


class WebScanner(object):
    def __init__(self):
        self.__author__ = "tahaafarooq"
        self.found_directories = []
        self.stacks = []

    def scan_directory(self, url: str, wordlist: str):
        with open(wordlist, "r") as file:
            directories = file.read().splitlines()

        for directory in directories:
            full_url = f"{url}/{directory}"
            res = requests.get(full_url)
            if res.status_code == 200:
                self.found_directories.append(directory)
                print(f"[+] Directory Found: {full_url} [-]")
            else:
                print(f"[-] Directory Not Found: {full_url} [-]")

        return self.found_directories

    def get_tech_stacks(self, url: str):
        apps, errors = wappalyzer.detect(url)
        if not errors:
            for app in apps:
                data = {
                    "Techonology": app['name'],
                    "Categories": f"{', '.join(app['categories'])}",
                    "Versions": f"{', '.join(app['versions'])}"
                }
                self.stacks.append(data)
            return self.statcks
        else:
            return "Not Found"

    def