# Artemis
[<img src="artemis.png" width="150"/>](artemis.png)

[![python](https://img.shields.io/badge/python-3.10+-blue.svg?logo=python&labelColor=yellow)](https://www.python.org/downloads/)
[![platform](https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-red.svg)](https://github.com/tahaafarooq/Artemis)
[![License](https://img.shields.io/:license-MIT-green.svg)]()

A community package-based tool security framework that simplifies carrying out scans, and pentests upon certain scope while performing security penetration testing and researches.

# Support
[![Donate to MobSF](https://user-images.githubusercontent.com/4301109/117404264-7aab5480-aebe-11eb-9cbd-da82d7346bb3.png)](https://www.patreon.com/OpenSourcifyWithTahaa)

If you find Artemis helpful, please consider donating :)

*Let's make an open-source time-changing tool!*

---

# Documentation
### Installation
There are two main ways to install this as displayed below;

**PYPI**
```
┌──(kali㉿kali)-[~/]
└─$ pip3 install artemispy
```

**SETUP**

```
┌──(kali㉿kali)-[~/Desktop/Artemis]
└─$ sudo python3 setup.py install
<-SNIP->
```

### Configuration

Create a **.env** file anywhere in your computer, add to it with API Keys from whoisxmlapi, shodan and vulners:

```dotenv
VULNERS_API_KEY=<SNIP>
SHODAN_API_KEY=<SNIP>
WHOISXML_API_KEY=<SNIP>
```

You can get the API key for each of the following respectively from the links below:

1. [Vulners](https://vulners.com/)
2. [Shodan](https://shodan.io)
3. [WhoisXMLAPI](https://user.whoisxmlapi.com/)

### IP SCAN (WHOIS)
##### WHOIS LOOKUP

```python
from artemispy.scanner import IPScanner

ip_object = IPScanner("/path/to/.env") # loads the .env file with the API keys
result = ip_object.whois_lookup("tahaafarooq.dev") # specify the domain inside the whois_lookup(arg) function

print(result) # print the response
{'WhoisRecord': {'domainName': 'tahaafarooq.dev', 'parseCode': 8, 'audit': {'createdDate': '2023-06-22 23:41:55 UTC', 'updatedDate': '2023-06-22 23:41:55 UTC'}<-SNIP->
```

Start of by importing `IPScanner` from `artemispy.scanner` which contains all the classes and functions for scanning.

Create a variable and then the value as the class loaded with the path to your **.env** file.

The `result` variable contains the class with the function whois_lookup() which takes an argument of a domain name that is to be scanned.

##### DNS LOOKUP

```python
from artemispy.scanner import IPScanner

ip_object = IPScanner("/path/to/.env") # loads the .env file with the API keys
result = ip_object.dns_lookup("tahaafarooq.dev") # specify the domain inside the dns_lookup(arg) function

print(result) # print the response
```

This will perform a DNS lookup and provide you with a JSON output of the response gathered.

##### IPGEO LOOKUP
```python
from artemispy.scanner import IPScanner

ip_object = IPScanner("/path/to/.env") # loads the .env file with the API keys
result = ip_object.ipgeo_lookup("172.217.170.14") # specify the domain inside the ipgeo_lookup(IPV4/IPV6) function

print(result) # print the response
{'ip': '172.217.170.14', 'location': {'country': 'ZA', 'region': 'Gauteng', 'city': 'Johannesburg', 'lat': -26.20227, 'lng': 28.04363, 'postalCode': '', 'timezone': '+02:00', 'geonameId': 993800}, 'domains': ['jnb02s02-in-f14.1e100.net', 'sb.l.google.com', 'scnservers.net'], 'as': {'asn': 15169, 'name': 'GOOGLE', 'route': '172.217.0.0/16', 'domain': 'https://about.google/intl/en/', 'type': 'Content'}, 'isp': 'Google LLC', 'connectionType': ''}
```

The `ipgeo_lookup()` function takes an argument as an IPv4 or IPv6 address.

##### SUBDOMAIN LOOKUP

```python
from artemispy.scanner import IPScanner

ip_object = IPScanner("/path/to/.env") # loads the .env file with the API keys
result = ip_object.subdomain_lookup("tahaafarooq.dev") # specify the domain inside the subdomain_lookup(domain) function

print(result) # print the response
```

### NETWORK SCAN
##### PORT SCAN

```python
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.5.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from artemispy.scanner import NetworkScanner

In [2]: net_object = NetworkScanner("127.0.0.1")

In [3]: port_scan = net_object.port_scanner()

In [4]: print(port_scan)
['Port : 22 --> State: open', 'Port : 80 --> State: open', 'Port : 3389 --> State: open', 'Port : 46247 --> State: open']
```

First, import `NetworkScanner` class from `artemispy.scanner` then we create a variable and add our class to it with the value of our IP to scan. Calling for the function `port_scanner()` should get the work done for you!

##### SERVICE DISCOVERY

```python
Python 3.11.2 (main, Mar 13 2023, 12:18:29) [GCC 12.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.5.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from artemispy.scanner import NetworkScanner

In [2]: net_object = NetworkScanner("127.0.0.1")

In [3]: service_scan = net_object.service_discovery()
Host: 127.0.0.1

In [4]: print(service_scan)
['ssh', 'http', 'ms-wbt-server', 'unknown']
```

`service_discovery()` function provides the services names running on the ports that are open from the port scan.

**MORE TO BE WRITTEN**

Star it up if you think it's helpful :)

# Contact
[Tahaa Farooq - Twitter](https://twitter.com/tahaafarooq)

[Tahaa Farooq - Email](mailto:tahacodez@gmail.com)

*LOGO ArtWork By [witchdocsec](https://github.com/witchdocsec/)*
