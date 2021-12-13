<h1 align="center">log4j-scan</h1>
<h4 align="center">A fully automated, accurate, and extensive scanner for finding vulnerable log4j hosts</h4>

![](https://dkh9ehwkisc4.cloudfront.net/static/files/80e52a5b-7d72-44c2-8187-76a2a58f5657-demo.png)


# Features

- Support for lists of URLs.
- Fuzzing for more than 60 HTTP request headers (not only 3-4 headers as previously seen tools).
- Fuzzing for HTTP POST Data parameters.
- Fuzzing for JSON data parameters.
- Supports DNS callback for vulnerability discovery and validation.
- WAF Bypass payloads.

# Description

We have been researching the Log4J RCE (CVE-2021-44228) since it was released, and we worked in preventing this vulnerability with our customers. We are open-sourcing an open detection and scanning tool for discovering and fuzzing for Log4J RCE CVE-2021-44228 vulnerability. This shall be used by security teams to scan their infrastructure for Log4J RCE, and also test for WAF bypasses that can result in achiving code execution on the organization's environment.

It supports DNS OOB callbacks out of the box, there is no need to setup a DNS callback server.





# Usage

```python
$ python3 log4j-scan.py -h
[•] CVE-2021-44228 - Apache Log4j RCE Scanner
[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
[•] Secure your External Attack Surface with FullHunt.io.
usage: log4j-scan.py [-h] [-u URL] [-l USEDLIST] [--request-type REQUEST_TYPE] [--headers-file HEADERS_FILE] [--run-all-tests] [--exclude-user-agent-fuzzing]
                     [--wait-time WAIT_TIME] [--waf-bypass] [--dns-callback-provider DNS_CALLBACK_PROVIDER]
                     [--dns-callback-interactsh-server DNS_CALLBACK_INTERACTSH_SERVER] [--dns-callback-interactsh-token DNS_CALLBACK_INTERACTSH_TOKEN]
                     [--custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST]

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check a single URL.
  -l USEDLIST, --list USEDLIST
                        Check a list of URLs.
  --request-type REQUEST_TYPE
                        Request Type: (get, post) - [Default: get].
  --headers-file HEADERS_FILE
                        Headers fuzzing list - [default: headers.txt].
  --run-all-tests       Run all available tests on each URL.
  --exclude-user-agent-fuzzing
                        Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.
  --wait-time WAIT_TIME
                        Wait time after all URLs are processed (in seconds) - [Default: 5].
  --waf-bypass          Extend scans with WAF bypass payloads.
  --dns-callback-provider DNS_CALLBACK_PROVIDER
                        DNS Callback provider (Options: dnslog.cn, interact.sh) - [Default: interact.sh].
  --dns-callback-interactsh-server DNS_CALLBACK_INTERACTSH_SERVER
                        If interact.sh is the DNS Callback provider then the url can be specified - [Default: interact.sh].
  --dns-callback-interactsh-token DNS_CALLBACK_INTERACTSH_TOKEN
                        If interact.sh is the DNS Callback provider then the token can be specified.
  --custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST
                        Custom DNS Callback Host.
```

## Scan a Single URL

```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local
```

## Scan a Single URL using all Request Methods: GET, POST (url-encoded form), POST (JSON body)


```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local --run-all-tests
```

## Discover WAF bypasses on the environment.

```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local --waf-bypass
```

## Scan a list of URLs

```shell
$ python3 log4j-scan.py -l urls.txt
```

## Scan a single URL with custom interactsh server

```shell
$ python3 log4j-scan.py -u https://log4j.lab.secbot.local --dns-callback-interactsh-server interact.sh --dns-callback-interactsh-token '<replaceme>'
```


# Installation

```
$ pip3 install -r requirements.txt
```


# About FullHunt

FullHunt is the next-generation attack surface management platform. FullHunt enables companies to discover all of their attack surfaces, monitor them for exposure, and continuously scan them for the latest security vulnerabilities. All, in a single platform, and more.

FullHunt provides an enterprise platform for organizations. The FullHunt Enterprise Platform provides extended scanning and capabilities for customers. FullHunt Enterprise platform allows organizations to closely monitor their external attack surface, and get detailed alerts about every single change that happens. Organizations around the world use the FullHunt Enterprise Platform to solve their continuous security and external attack surface security challenges.

# Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of log4j-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.


# License
The project is licensed under MIT License.


# Author
*Mazin Ahmed*
* Email: *mazin at FullHunt.io*
* FullHunt: [https://fullhunt.io](https://fullhunt.io)
* Website: [https://mazinahmed.net](https://mazinahmed.net)
* Twitter: [https://twitter.com/mazen160](https://twitter.com/mazen160)
* Linkedin: [http://linkedin.com/in/infosecmazinahmed](http://linkedin.com/in/infosecmazinahmed)
