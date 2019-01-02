# **** IP Scanner ****

#! /usr/bin/python

import sys
from datetime import datetime
try:
    from logging import getLogger, ERROR         # importing scapy module in exception handling as it is an external module(a third party module)
    getLogger('scapy.runtime').setLevel(ERROR)   # if module is not imported then proper error handling is done
    from scapy.all import *			 # getLogger function of logging prevent scapy from spilling out its own errors when we import it
    conf.verb = 0
except ImportError:
    print("[!] Failed to import scapy")
    sys.exit(1)


class ArpEnumerator(object):                                             # Class Defination
    def __init__(self, interface=False, passive=False, range=False):     # Constructor for the class with default values "False"      
        self.interface = interface
        self.passive = passive
        self.range = range
        self.discovered_hosts = {}					 # An empty Dictionary to store the information of the discovered hosts
        self.filter = 'arp'						 
        self.startime = datetime.now()					 # datetime is used to keep track of the time


    # Passive mode

    def passive_handler(self, pkt):					 # Function to handle passive mode
        try:								 # this function checks if the current host is already in the dictionary then move on else 
            if not pkt[ARP].psrc in self.discovered_hosts.keys():        # add the host in the dictionary after printing its IP and Mac address
                print("{} - {}".format(pkt[ARP].psrc, pkt[ARP].hwsrc))
		self.discovered_hosts[pkt[ARP].psrc] = pkt[ARP].hwsrc
        except Exception:
            return
        except KeyboardInterrupt:
            return

    def passive_sniffer(self):						 # Function performing sniff
        if not self.range:						 # checking the range variable if it contain something or not
            print("[*] No Range Given; Sniffing All ARP Traffic")
        else:
            self.filter += ' and (net {})'.format(self.range)		 # then update the  filter variable as per the input 
        print("[*] Sniffing Started on {}\n".format(self.interface))	 # this way we can sniff the specific range of Ip address
        try:
            sniff(filter=self.filter, prn=self.passive_handler, store=0) # store is assigned to 0 because we won't inspect these packets further
        except Exception:						 # We placed sniffing in a try/except block so that we can interrupt the process by Keyboard Interrupt 
            print("\n[!] An Unknown Error Occured")
            return
        print("[*] Sniffing Stopped")
        self.duration = datetime.now() - self.startime
        print("[*] Sniff Duration: {}".format(self.duration))

    # Active mode

    def active_scan(self):						 # Function to handle Acctive mode
        print("[*] Scanning For Hosts...")
        sys.stdout.flush()						 # flush() forces the buffer to be flushed means all the data of the buffer is written on terminal
        try:
            ans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=self.range), timeout=2, iface=self.interface, inter=0.1)[0]  
        except Exception:						 # srp() function from scapy module sends out ARP requests for all hosts in the range specied by the user
            print("Fail")						 # try/except block to check any error
            print("[!] An Unknown Error Occured")			 # the resposnse of ARP request stored in the list named "ans"
            return
        print("Done\n[*] Displaying Discovered Hosts:\n")
	print("IP Address \tMac Address\n")
        for snd, rcv in ans:						# iterate through the list to add the hosts in our dictionary
            self.discovered_hosts[rcv[ARP].psrc] = rcv[ARP].hwsrc
            print("{} - {}".format(rcv[ARP].psrc, rcv[ARP].hwsrc))      
        print("\n[*] Scan Complete")
        self.duration = datetime.now() - self.startime			# calculating total time after scan is complete
        print("[*] Sniff Duration: {}".format(self.duration))
        return

    def output_results(self, path):					# Function to write output in a file
        print("[*] Writing To Output File...")
        try:

            with open(path, 'w')as file:				# using with() writing a file
                file.write('Dicovered Hosts:\n')
                for key, val in self.discovered_hosts.items():	
                    file.write("{} - {}\n".format(key, val))
                file.write("\nScan Duration: {}".format(self.duration))
            print("[DONE]\n[*] Successfully Wrote to {}".format(path))
            return
        except IOError:
            print("\n[!] Failed To Write Output File")			# try/except block to handle any error while writing data to the file
            return


def main():
    import argparse										# importing argparse module to pass args at runtime
    parser = argparse.ArgumentParser(description="ARP-Based Network Enumeration Tool")		# Connecting arg-parser
    parser.add_argument('-i', '--interactive', help='Network interface to scan/sniff on',	# different args- interface, range, passive, output-file
                        action='store', dest='interface', default=False)
    parser.add_argument('-r', '--range', help='Range of IPs in CIDR notation',
                        action='store', dest='range', default=False)
    parser.add_argument('--passive', help='Enable passive mode (No packet sent sniff only)',
                        action='store_true', dest='passive', default=False)
    parser.add_argument('-o', help="Output scan results to text file",
                        action='store', dest='file', default=False)
    args = parser.parse_args()

    if not args.interface:						# condition for checking interface is given or not
        parser.error('No network interface given')
    elif (not args.passive) and (not args.range):
        parser.error('No range specified for active scan')
    else:
        pass

    if args.passive:             # passive scan with range
        if not not args.range:
            enum = ArpEnumerator(interface=args.interface, passive=True, range=args.range)
            enum.passive_sniffer()
        else:			 # passive scan without range 
            enum = ArpEnumerator(interface=args.interface, passive=True)
            enum.passive_sniffer()
    else:			 # active scan with range
        enum = ArpEnumerator(interface=args.interface, range=args.range)
        enum.active_scan()

    if not not args.file:	# condition for writing output file
        enum.output_results(args.file)

if __name__ == '__main__':  
    main()
