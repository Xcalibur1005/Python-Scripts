# NMAP_FUNCTION_EMULATION
This repository contains "ICMP_PING_SWEEP" and "PORT_SCANNER" scripts.

##ICMP_PING_SWEEP.py##
This script uses "Scapy" module to send TCP SYN packets to hosts. Depending on the response of the SYN request, the script determines if host is up or not.
It takes two arguments, '-i' for single IP address and '-r' for range of an IP address to scan.
Also, the script validates if IP provided is valid IP or not using regex.


##PORT_SCANNER.py##
This script uses "Scapy" module to send ICMP requests to TCP ports. Depending on the response of the ICMP request, the script determines if port is open, closed or blocking our requests.
It takes 3 arguments, '-d' for target IP to be scanned, '-s' for starting port range and '-e' for end of the port range to be scanned.
If port range is not defined, script will scan first 1000 ports by default.


