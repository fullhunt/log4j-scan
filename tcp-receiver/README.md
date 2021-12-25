# Simple Python TCP receiver

Simple TCP receiver, which logs and writes in `output.txt` file any IP trying to connect on it (port 80, most common).

It is for `--custom-tcp-callback-host` option usage of *log4j-scan*.

Usage:

```shell
nohup python3 log4ShellReceiver.py 2>&1 &
```
