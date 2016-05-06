import logging,argparse,sys
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from netaddr import *

## Arguments to the script ##
parser=argparse.ArgumentParser(description='This is ICMP Ping Sweep script')
parser.add_argument('-i','--ip',help='Provide IP to be scanned', required=False)
parser.add_argument('-r','--range',help='Provide IP range to be scanned. Ex: -r 192.168.0.0/24',required=False)
args=parser.parse_args()

## Main Function ##
def ICMP_PING_SWEEP(host):
        ping=sr1(IP(dst=str(host))/ICMP(),timeout=2,verbose=0)
        if (str(type(ping))=="<type 'NoneType'>"):
                print(str(host) + ":" + " is down.")
        elif(int(ping.getlayer(ICMP).type)== 3 and int(ping.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                print(str(host) + ":" + " is blocking ICMP ping.")
        else:
                print(str(host) + ":" + " is alive.")


## Define range to be scanned ##
if args.ip:
        host=args.ip
        ICMP_PING_SWEEP(host)
elif args.range:
        host=args.range
        for ip in IPNetwork(host).iter_hosts():
                ICMP_PING_SWEEP(ip)
