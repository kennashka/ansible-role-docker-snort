

Super Computer 


sudo apt-get update

sudo apt-get install     apt-transport-https     ca-certificates     curl     gnupg     lsb-release -y


curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg


echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null



INSTALL DOCKER ENGINE

 sudo apt-get update

 sudo apt-get install docker-ce docker-ce-cli containerd.io -y



 

sudo docker run hello-world


docker ps

docker ps -a



sudo docker pull linton/docker-snort

————————————————————————————
Attach the snort in container to have full access to the network



docker run -it --rm --net=host --cap-add=NET_ADMIN linton/docker-snort /bin/bash

 vim /etc/snort/rules/local.rules


snort -i eth0 -c /etc/snort/etc/snort.conf -A console
————————————————












For testing it's work. Add this rule in the file at /etc/snort/rules/local.rules

 vim /etc/snort/rules/local.rules

alert icmp any any -> any any (msg:"Pinging...";sid:1000004;)


Running Snort and alerts output to the console (screen).
$ snort -i eth0 -c /etc/snort/etc/snort.conf -A console


Ping in the container then the alert message will show on the console
ping 8.8.8.8



172.31.33.156

Attacker Commands:

Identify NMAP Ping Scan:				

nmap -sP 172.31.33.156--disable-arp-ping

Identify NMAP TCP Scan:								

nmap -sT -p22 18.191.148.196

Identify NMAP XMAS Scan:		

nmap -sX -p22 18.191.148.196

Identify NMAP FIN Scan:	

nmap -sF -p22 18.191.148.196

Identify NMAP NULL Scan:			

nmap -sN -p22 18.191.148.196

Identify NMAP UDP Scan:						

nmap -sU -p68 18.191.148.196

Alert for FTP traffic:							

telnet 18.191.148.196 21

Alert for ‘terrorism’ in content outgoing from internal network:


Implement rules to detect SQL injection and Cross Site Scripting (XSS) attacks: 18.191.148.196/sqli/Less-1/?id=1'




# ----------------
# LOCAL RULES
# ----------------
# This file intentionally does not come with signatures.  Put your local
# additions here.

# Identify NMAP Ping Scan
# alert icmp any any -> 172.31.33.156 any (msg: "This is proof that it works."; dsize:0;sid:10000004; rev: 1;)

# Identify NMAP TCP Scan
# alert tcp any any -> 172.31.33.156  22 (msg: "NMAP TCP Scan";sid:10000005; rev:2; )

# Identify NMAP XMAS Scan
# alert tcp any any -> 172.31.43.202 22 (msg:"Nmap XMAS Tree Scan"; flags:FPU; sid:1000006; rev:1; )

# Identify NMAP FIN Scan
# alert tcp any any -> 172.31.43.202 22 (msg:"Nmap FIN Scan"; flags:F; sid:1000008; rev:1;)

# Identify NMAP NULL Scan
# alert tcp any any -> 172.31.43.202 22 (msg:"Nmap NULL Scan"; flags:0; sid:1000009; rev:1; )

# Identify NMAP UDP Scan
# alert udp any any -> 172.31.43.202 any ( msg:"Nmap UDP Scan"; sid:1000010; rev:1; )

# Alert for FTP traffic
# alert tcp any any -> 172.31.43.202 21 ( msg:"FTP traffic"; sid:1000002; rev:1; )

# Alert for terrorism in content outgoing
# alert tcp any any -> any any ( msg:"TRIGGERED"; sid:5000000; content:"_terrorism_"; rev:1; )

# Implement rules to detect SQL injection and Cross Site Scripting (XSS) attacks
# alert tcp any any -> any 80 (msg: "Error Based SQL Injection Detected"; content: "%27" ; sid:100000011; )
# alert tcp any any -> any 80 (msg: "Error Based SQL Injection Detected"; content: "22" ; sid:100000012; )
