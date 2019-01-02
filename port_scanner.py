# Port Scanner

from socket import *
import sys
import time
from datetime import datetime

host = ''
max_port = 1000 # TODO: change these before submission
min_port = 1


def scan_host(host, port, r_code=1):  # host=IP, port=port no.to be scanned and r_code is just a variable name 
    try:
        s = socket(AF_INET, SOCK_STREAM)
	# creating an object of class socket
        # here AF_INET is the address family for ipv4 uses host and port

        code = s.connect_ex((host, port))
	# s.connect_ex() function returns an error no. instead of exception
        # if no error then it returns zero. No error means port is open.

        if code == 0:
            r_code = code
        s.close()
    except Exception as e:
        pass
    return r_code


def main():

    try:
        host = raw_input("[*] Enter Target Host Address: ")
    except KeyboardInterrupt:
        print("\n\n[*] User Requested An Interrupt.")
        print("[*] Application Shutting Down.")
        sys.exit(1)

    hostip = gethostbyname(host)
    print("\n[*] Host: {} IP {}".format(host, hostip))
    print("[*] Scanning Started At {}...\n".format(time.strftime("%H:%M:%S")))
    start_time = datetime.now()   # Using datetime module for current time

    for port in range(min_port, max_port):
        try:
            response = scan_host(host, port)   # calling function for checking open ports

            if response == 0:
                print("[*] Port {}: Open".format(port))
        except Exception as e:
            pass

    stop_time = datetime.now()
    total_time_duration = stop_time - start_time
    print("[*] Scanning Finished At {}...".format(time.strftime("%H:%M:%S")))  # strftime is tring format for time
    print("[*] Scanning Duration: {}...".format(total_time_duration))

if __name__ == '__main__':
    main()
