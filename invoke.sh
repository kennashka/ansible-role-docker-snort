#!/bin/bash

#Author: Kennashka


sudo apt-get update

sudo apt-get install     apt-transport-https     ca-certificates     curl     gnupg     lsb-release -y


curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg


echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null



#INSTALL DOCKER ENGINE

 sudo apt-get update

 sudo apt-get install docker-ce docker-ce-cli containerd.io -y



 # Test out docker

sudo docker run hello-world


docker ps

docker ps -a


# install snort 

sudo docker pull linton/docker-snort

# Attach the snort in container to have full access to the network



docker run -it --rm --net=host --cap-add=NET_ADMIN linton/docker-snort /bin/bash

 # vim /etc/snort/rules/local.rules


# snort -i eth0 -c /etc/snort/etc/snort.conf -A console
————————————————












# For testing add  rule in the file at /etc/snort/rules/local.rules

# vim /etc/snort/rules/local.rules

# alert icmp any any -> any any (msg:"Pinging...";sid:1000004;)


# Running Snort and alerts output to the console (screen).
# snort -i eth0 -c /etc/snort/etc/snort.conf -A console


# Ping in the container then the alert message will show on the console
# ping 8.8.8.8



# Attacker Commands:

# Identify NMAP Ping Scan:				

# nmap -sP 172.31.33.156--disable-arp-ping

# Identify NMAP TCP Scan:								

# nmap -sT -p22 18.191.148.196

# Identify NMAP XMAS Scan:		

# nmap -sX -p22 18.191.148.196

# Identify NMAP FIN Scan:	

# nmap -sF -p22 18.191.148.196

# Identify NMAP NULL Scan:			

# nmap -sN -p22 18.191.148.196

# Identify NMAP UDP Scan:						

# nmap -sU -p68 18.191.148.196

# Alert for FTP traffic:							

# telnet 18.191.148.196 21

# Alert for ‘terrorism’ in content outgoing from internal network:


# Implement rules to detect SQL injection and Cross Site Scripting (XSS) attacks: 18.191.148.196/sqli/Less-1/?id=1'


