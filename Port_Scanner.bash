#!/bin/bash
#Refered from "Coding for Pentesters" by Jason Andress and Ryan Linn

#Asigning Variables to Arguments
host=$1
startport=$2
endport=$3

#Ping Function to check is system is up
function pingscan
{
echo "Initiating Ping Scan..."
ping=`ping -c 1 $host | grep bytes | wc -l`
if [ "$ping" -gt 1 ];then
	echo "$host is up";
else
	echo "$host is down, exiting program";
	exit
fi
}

#Port Scan Function
function portscan
{
echo "Initiating Port Scan..."
for ((counter=$startport; counter<=$endport; counter++))
do
	(echo >/dev/tcp/$host/$counter) > /dev/null 2>&1 && echo "$counter open"
done
}

#Calling Functions
pingscan
portscan
