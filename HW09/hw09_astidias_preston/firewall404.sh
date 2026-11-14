#!/bin/bash

# 1.) flush and delete all previously defined rules and chains
sudo iptables -t filter -F
sudo iptables -t filter -X

sudo iptables -t mangle -F
sudo iptables -t mangle -X

sudo iptables -t nat -F
sudo iptables -t nat -X

sudo iptables -t raw -F
sudo iptables -t raw -X

# 2.) write a rule that only rejects packets that originate from f1.com
sudo iptables -A INPUT -s 67.199.248.12 -j REJECT  
sudo iptables -A INPUT -s 67.199.248.13 -j REJECT

# 3.) for all outgoing packets, change their source ip address to your own machine's ip address  
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 4.) write a rule to protect yourself against indiscriminate and nonstop scanning of ports on your machine
sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -m limit --limit 5/min --limit-burst 7 -j ACCEPT
sudo iptables -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST SYN -j DROP

# 5.) write a rule to protect yourself from a SYN-flood attack by limiting the number of incoming new connection requests to 1 per second once your machine has reached 500 requests
sudo iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -m limit --limit 1/s --limit-burst 500 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j DROP
 
# 6.) write a rule to allow full loopback access on your machine i.e. access using localhost
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# 7.) write a port forwarding rule that routes all traffic arriving on port 8888 to port 25565. Make sure you specify the correct table and chain. subsequently, the target for the rule should be DNAT.
sudo iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination :25565

# 8.) write a rule that only allows outgoing ssh connections to engineering.purdue.edu. you will need two rules, one for the INPUT chain and one for the OUTPUT chain and one on the FILTER table. make sure to specify the correct options for the --state suboption for both rules.
sudo iptables -A OUTPUT -p tcp -d engineering.purdue.edu --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp -s engineering.purdue.edu --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow established and related connections
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 9.) drop any other packets if they are not caught by the above rules
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
