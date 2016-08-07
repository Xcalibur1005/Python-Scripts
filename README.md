# PYTHON SCRIPTS
This repository contains scripts that are handy in Penetration Testing, written in Python.

#ICMP_PING_SWEEP.py
This script uses "Scapy" module to send TCP SYN packets to hosts. Depending on the response of the SYN request, the script determines if host is up or not.
It takes two arguments, '-i' for single IP address and '-r' for range of an IP address to scan.
Also, the script validates if IP provided is valid IP or not using regex.
This program is compatible with 'Python 2.7'.


#PORT_SCANNER.py
This script uses "Scapy" module to send ICMP requests to TCP ports. Depending on the response of the ICMP request, the script determines if port is open, closed or blocking our requests.
It takes 3 arguments, '-d' for target IP to be scanned, '-s' for starting port range and '-e' for end of the port range to be scanned.
If port range is not defined, script will scan first 1000 ports by default.
This program is compatible with 'Python 2.7'.

#ICMP_PING_SWEEP_MULTITHREADING.py
This script is extended version of 'ICMP_PING_SWEEP.py'. It uses multithreading to scan systems more quickly.
This program is compatible with 'Python 2.7'.

#PORT_SCANNER_MULTITHREADING.py
This script is extended version of 'PORT_SCANNER.py'. It uses multithreading to scan ports more quickly.
This program is compatible with 'Python 3.5'.


