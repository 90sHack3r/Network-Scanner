# User interaction file 

import port_scanner
import Ip_scanner
from pyfiglet import figlet_format
from termcolor import colored


while True:
    print("\n")
    text = figlet_format("NETWORK SCANNER", font = "poison")
    ftext = colored(text, color="cyan")
    print(ftext)
    print("\n1. IP Scanner\n2. Port Scanner\n3. Quit\n")
    ans = int(input("[*]Select An Options to Continue:"))

    if ans == 1:
        Ip_scanner.main()
    elif ans == 2:
        port_scanner.main()
    elif ans == 3:
	print("\n[*]Thank you for using")
        print("\n[*]Shutting Down....\n")
        exit(1)
    else:
        print("[!]Please Select an Appropriate Option....")
