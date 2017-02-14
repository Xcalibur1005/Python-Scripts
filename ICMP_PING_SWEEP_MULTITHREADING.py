#!/usr/bin/python

import threading, time, argparse, sys, random, logging, re
from Queue import Queue
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from netaddr import *

## Arguments to the script ##
parser=argparse.ArgumentParser(description='This is ICMP Ping Sweep script')
parser.add_argument('-i','--ip',help='Provide IP to be scanned.Ex: -i 10.0.0.10', required=False)
parser.add_argument('-r','--range',help='Provide IP range to be scanned. Ex: -r 192.168.0.0/24',required=False)
args=parser.parse_args()

## Locking the variable ##
print_lock = threading.Lock()

## Main Program ##
def ICMP_PING_SWEEP(host):
	ping=sr1(IP(dst=str(host))/ICMP(),timeout=2,verbose=0)
	if (str(type(ping))=="<type 'NoneType'>"):
#		print(str(host) + ":" + " is down.")
		pass
	elif (int(ping.getlayer(ICMP).type)== 3 and int(ping.getlayer(ICMP).code) in [1,2,3,9,10,13]):
		print(str(host) + ":" + " is blocking ICMP ping.")
	else:
		print(str(host) + ":" + " is alive.")	

## Threading Function ##
def threader():
	while True:
		worker = q.get()
		ICMP_PING_SWEEP(worker)
		q.task_done()

q = Queue.Queue()

## Defining number of threads ##
for x in range(10):
	t = threading.Thread(target = threader)
	t.daemon = True
	t.start()

start_time = time.time()

## Checking for valid IP syntax ## Defining number of jobs to be executed ##
if args.ip:
        host=args.ip
        if re.match("^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$",host):
                ICMP_PING_SWEEP(host)
        else:
                print("Invalid IP")

elif args.range:
	host=args.range
	for worker in IPNetwork(host).iter_hosts():
		q.put(worker)
	
q.join()

print("Entire job took: ", time.time() - start_time)
