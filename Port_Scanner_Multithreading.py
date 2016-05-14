#!/usr/bin/python

import threading, time, argparse, sys, random, logging
from queue import Queue
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

## Arguments to the script ##
parser = argparse.ArgumentParser(description='This is a port scanning script')
parser.add_argument('-d','--dst_ip', help='Destination IP to be scanned',required=True)
parser.add_argument('-s','--start_port_range',type=int,help='Give starting range of ports to be scanned',required=False)
parser.add_argument('-e','--end_port_range',type=int,help='Give end range of ports to be scanned',required=False)
args = parser.parse_args()

## Defining host to be scanned ##
if (args.dst_ip):
        host=args.dst_ip
else:
        print("Host not defined correctly. See -h for correct syntax")

## Defining ports to be scanned ##
if (args.start_port_range) and (args.end_port_range):
        start = args.start_port_range
        end = args.end_port_range
else:
        start = 1
        end = 1000

## Locking the variable ##
print_lock = threading.Lock()

## Main Program ##
def Port_Scanner(port):
	scan=sr1(IP(dst=host)/TCP(sport=80,dport=port,flags="S"),timeout=2,verbose=0)
	if (str(type(scan)) == "<type 'NoneType'>"):
		print(str(host) + ":" + str(port) + " is filtered")
	elif(scan.haslayer(TCP)):
		if(scan.getlayer(TCP).flags == 0x12):
			print(str(host) + ":" + str(port) + " is open")
	#	elif(scan.getlayer(TCP).flags == 0x14):
	#		print(str(host) + ":" + str(port) + " is closed")
	elif(scan.haslayer(ICMP)):
		if(int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			print(str(host) + ":" + str(port) + " is filtered")		

## Threading Function ##
def threader():
	while True:
		worker = q.get()
		Port_Scanner(worker)
		q.task_done()

q = Queue()

## Defining number of threads ##
for x in range(10):
	t = threading.Thread(target = threader)
	t.daemon = True
	t.start()

start_time = time.time()

## Defining number of jobs to be executed ##
for worker in range(int(start), int(end)):
	q.put(worker)

q.join()

print("Entire job took: ", time.time() - start_time)