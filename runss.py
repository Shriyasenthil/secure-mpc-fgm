#!/usr/bin/env python3
from subprocess import Popen, PIPE
import time


def run_script(name, path):
    print(f"Starting {name}...", flush=True)
    return Popen(['python3', path], stdout=PIPE, stderr=PIPE, universal_newlines=True)

if __name__ == '__main__':
    try:
        proc1 = run_script("Server1","server1.py")
        time.sleep(2)  
        proc2 = run_script("Server2", "server2.py")
        stdout2, stderr2 = proc2.communicate()
        stdout1, stderr1 = proc1.communicate()

        print("\nServer1 Output")
        print(stdout1)
        print("Server1 Errors")
        print(stderr1)

        print("\nServer2 Output")
        print(stdout2)
        print("Server2 Errors")
        print(stderr2)

    except Exception as e:
        print("error occurred when running servers:", e)