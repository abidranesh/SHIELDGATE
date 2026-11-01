# Shieldgate rule test fixture -- intentionally vulnerable code, never run.
import os
import subprocess

def bad(host, path):
    # ruleid: shieldgate.python.subprocess-shell-true
    subprocess.run("ping -c 1 " + host, shell=True)
    # ruleid: shieldgate.python.subprocess-shell-true
    subprocess.check_output(f"ls {path}", shell=True)
    # ruleid: shieldgate.python.os-system-injection
    os.system("rm -rf " + path)
    # ruleid: shieldgate.python.os-system-injection
    os.popen(f"cat {path}")

def good(host):
    # ok: shieldgate.python.subprocess-shell-true
    subprocess.run(["ping", "-c", "1", host])
    # ok: shieldgate.python.subprocess-shell-true
    subprocess.run("uptime", shell=True)
    # ok: shieldgate.python.os-system-injection
    os.system("clear")
