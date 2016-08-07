#!/bin/bash
#This script works only for /24 subnet.

#Asigning Variables to Arguments
subnet=$1
startip=$2
endip=$3

#Ping Function to check is system is up
function pingscan
{
echo "Initiating Ping Scan..."
for ((counter=$startip; counter<=$endip; counter++))
do
	ip=$subnet.$counter
	ping=`ping -c 1 $ip | grep bytes | wc -l`
	if [ "$ping" -gt 1 ];then
		echo "$ip is up";
	else
		echo "$ip is down";
	fi
done
}

#Calling Functions
pingscan
