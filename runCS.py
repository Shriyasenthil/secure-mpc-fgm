#!/usr/bin/env python3
import subprocess
import time
import sys

if __name__ == '__main__':
    try:
        print("Starting Server2...", flush=True)
        proc_server2 = subprocess.Popen(['python3', 'server2.py'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True)

        time.sleep(1)

        print("Starting Server1...", flush=True)
        proc_server1 = subprocess.Popen(['python3', 'server1.py'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        universal_newlines=True)

        time.sleep(1)

        print("Starting Client...", flush=True)
        proc_client = subprocess.Popen(['python3', 'client.py'],
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       universal_newlines=True)

        stdout_client, stderr_client = proc_client.communicate()
        stdout_server1, stderr_server1 = proc_server1.communicate()
        stdout_server2, stderr_server2 = proc_server2.communicate()

      
        print("\n========= Server2 Output =========\n", stdout_server2)
        if stderr_server2.strip():
            print("========= Server2 Errors =========\n", stderr_server2)

        print("\n========= Server1 Output =========\n", stdout_server1)
        if stderr_server1.strip():
            print("========= Server1 Errors =========\n", stderr_server1)

        print("\n========= Client Output =========\n", stdout_client)
        if stderr_client.strip():
            print("========= Client Errors =========\n", stderr_client)

    except Exception as e:
        print("An error occurred while running the protocol:", str(e))
