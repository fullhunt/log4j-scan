# Frequently Asked Questions

## DNS callback error

```
Traceback (most recent call last):
File "/Users/user/src/log4j-scan/log4j-scan.py", line 362, in
main()
File "/Users/user/src/log4j-scan/log4j-scan.py", line 332, in main
dns_callback = Interactsh()
File "/Users/darkcode/src/log4j-scan/log4j-scan.py", line 195, in init
self.register()
File "/Users/user/src/log4j-scan/log4j-scan.py", line 206, in register
raise Exception("Can not initiate interact.sh DNS callback client")
Exception: Can not initiate interact.sh DNS callback client
```

It means that the DNS callback provider is down, it's blocked on your network, or you can not connect to the DNS callback provider due to networking issues. You can use an different DNS Callback provider (eg.. with `--dns-callback-provider dnslog.cn`), or you can use a custom DNS callback host with ` --custom-dns-callback-host`.

---

## Running with Python 2

```
File "log4j-scan.py", line 136
fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
```

It should be related to Python 2 compatibility. The tool requires a modern version of Python 3.

---

# Dependencies issue

```
File "/home/parallels/Log4j-RCE-Scanner/log4j-scan/log4j-scan.py", line 22, in
from Crypto.Cipher import AES, PKCS1_OAEP
ModuleNotFoundError: No module named 'Crypto'
```

This should be related to Pycrypto. Please install the latest Python PyCryptodome version. If you're still facing dependencies issues, you can use the Docker image.